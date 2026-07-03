"""
Priority 7 — Test suite for mutex extraction from PE artifacts.

Covers:
  _extract_strings          — ASCII + UTF-16LE string extraction
  _parse_pe_imports         — pure-Python PE32/PE32+ import table parser
  _classify_mutex_candidate — GUID / hex / known-malware classification
  _extract_mutex_candidates — candidate filtering and ranking
  _calculate_risk_score     — risk aggregation with mutex + import signals
  analyze_artifact          — full pipeline integration (P7 fields)
  POST /analyze/file        — multipart upload endpoint (API layer)
  POST /analyze/domain      — domain analysis (regression; uses query params)
  POST /analyze/ip          — IP analysis (regression; uses query params)

PE32 binary construction:
  _build_test_pe32() creates a minimal valid PE32 image with a real import
  directory table, allowing the parser tests to verify byte-level correctness
  without requiring any external PE files.
"""

import struct
import uuid as _uuid
import pytest
import pytest_asyncio

from asc_api.services.analyzer import (
    _extract_strings,
    _parse_pe_imports,
    _classify_mutex_candidate,
    _extract_mutex_candidates,
    _calculate_risk_score,
    analyze_artifact,
)


# ─── Synthetic PE32 builder ───────────────────────────────────────────────────

def _build_test_pe32(
    functions: list[str] | None = None,
    dll_name: str = "kernel32.dll",
) -> bytes:
    """
    Build a minimal valid PE32 binary with a real import directory table.

    File layout (little-endian):
      0x000–0x03F  DOS header   (64 bytes; e_lfanew=0x40)
      0x040–0x043  PE signature (4 bytes)
      0x044–0x057  IMAGE_FILE_HEADER (20 bytes)
      0x058–0x137  IMAGE_OPTIONAL_HEADER32 (224 bytes; Import DD at opt+104)
      0x138–0x15F  IMAGE_SECTION_HEADER for .idata (40 bytes)
      0x160–0x1FF  padding to FileAlignment=0x200
      0x200–0x3FF  section raw data (descriptors + INT + name entries)

    The section is mapped at VirtualAddress 0x2000.
    """
    functions = functions or []
    SECTION_RVA = 0x2000   # virtual address of section
    SECTION_RAW = 0x200    # file offset of section raw data

    # Section data layout:
    #   0x000: IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    #   0x014: null descriptor         (20 bytes)
    #   0x028: INT entries             ((len(functions)+1) × DWORD)
    #   0x028+(N+1)*4 : name entries + DLL name string

    INT_OFFSET = 0x028
    int_end    = INT_OFFSET + (len(functions) + 1) * 4   # end of INT table

    # Build name entries and record their RVAs
    name_rvas: list[int]    = []
    name_entries: list[bytes] = []
    cur_off = int_end

    for fn in functions:
        rva = SECTION_RVA + cur_off
        name_rvas.append(rva)
        entry = struct.pack("<H", 0) + fn.encode("ascii") + b"\x00"
        name_entries.append(entry)
        cur_off += len(entry)

    DLL_NAME_OFF = cur_off
    DLL_RVA      = SECTION_RVA + DLL_NAME_OFF
    dll_bytes    = dll_name.encode("ascii") + b"\x00"

    INT_RVA = SECTION_RVA + INT_OFFSET

    import_desc = struct.pack("<IIIII", INT_RVA, 0, 0, DLL_RVA, INT_RVA)
    null_desc   = b"\x00" * 20
    int_data    = (
        b"".join(struct.pack("<I", rva) for rva in name_rvas)
        + struct.pack("<I", 0)
    )

    section_content = (
        import_desc + null_desc + int_data
        + b"".join(name_entries) + dll_bytes
    )
    section_data = section_content.ljust(0x200, b"\x00")

    IMPORT_RVA  = SECTION_RVA
    IMPORT_SIZE = 40   # 2 descriptors × 20 bytes

    # IMAGE_OPTIONAL_HEADER32 (224 bytes)
    opt = bytearray(224)
    struct.pack_into("<H", opt,  0, 0x010B)       # Magic: PE32
    struct.pack_into("<I", opt, 16, 0x1000)       # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)       # BaseOfCode
    struct.pack_into("<I", opt, 24, SECTION_RVA)  # BaseOfData
    struct.pack_into("<I", opt, 28, 0x400000)     # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)       # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)        # FileAlignment
    struct.pack_into("<H", opt, 40, 4)            # MajorOSVersion
    struct.pack_into("<H", opt, 48, 4)            # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x3000)       # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)        # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)            # Subsystem: GUI
    struct.pack_into("<I", opt, 72, 0x40000)      # SizeOfStackReserve
    struct.pack_into("<I", opt, 76, 0x1000)       # SizeOfStackCommit
    struct.pack_into("<I", opt, 80, 0x100000)     # SizeOfHeapReserve
    struct.pack_into("<I", opt, 84, 0x1000)       # SizeOfHeapCommit
    struct.pack_into("<I", opt, 92, 16)           # NumberOfRvaAndSizes
    # DataDirectory[1] (Import) at offset 104  (DD[0] at 96 left as zeros)
    struct.pack_into("<I", opt, 104, IMPORT_RVA)
    struct.pack_into("<I", opt, 108, IMPORT_SIZE)

    # IMAGE_FILE_HEADER (20 bytes)
    # <H Machine><H Sections><I TS><I SymPtr><I NumSym><H OptSz><H Chars>
    file_hdr = struct.pack("<HHIIIHH",
        0x014C,  # Machine: i386
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        224,     # SizeOfOptionalHeader
        0x0002,  # Characteristics: executable
    )

    # IMAGE_SECTION_HEADER for .idata (40 bytes)
    # Name[8] + <I VirtSz><I VirtAddr><I RawSz><I RawPtr>
    #           <I PtrReloc><I PtrLN><H NumReloc><H NumLN><I Chars>
    sec_hdr = (
        b".idata\x00\x00"
        + struct.pack("<IIIIIIHHI",
            len(section_content),  # VirtualSize
            SECTION_RVA,           # VirtualAddress
            0x200,                 # SizeOfRawData
            SECTION_RAW,           # PointerToRawData
            0, 0,                  # reloc / linenumber ptrs
            0, 0,                  # counts
            0xC0000040,            # Characteristics: init_data | read | write
        )
    )

    # DOS header (64 bytes): MZ magic + e_lfanew = 0x40
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)

    headers = bytes(dos) + b"PE\x00\x00" + file_hdr + bytes(opt) + sec_hdr
    assert len(headers) <= SECTION_RAW, f"Headers overflow: {len(headers)} > {SECTION_RAW}"
    headers = headers.ljust(SECTION_RAW, b"\x00")

    return headers + bytes(section_data)


# ═══════════════════════════════════════════════════════════════════════════════
# TestExtractStrings
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractStrings:
    """ASCII + UTF-16LE string extraction."""

    def test_empty_data_returns_empty(self):
        assert _extract_strings(b"") == []

    def test_ascii_string_extracted(self):
        assert "Hello world" in _extract_strings(b"\x00Hello world\x00")

    def test_ascii_too_short_excluded(self):
        assert "Hi" not in _extract_strings(b"Hi\x00")   # 2 chars < min_len=4

    def test_ascii_exact_min_len_extracted(self):
        assert "ABCD" in _extract_strings(b"ABCD")        # exactly 4 chars

    def test_wide_string_extracted(self):
        wide = "Hello".encode("utf-16-le")
        assert "Hello" in _extract_strings(b"\x00\x00" + wide + b"\x00\x00")

    def test_mixed_ascii_and_wide(self):
        wide   = "WideStr".encode("utf-16-le")
        result = _extract_strings(b"AsciiStr\x00\x00" + wide)
        assert "AsciiStr" in result
        assert "WideStr"  in result

    def test_only_printable_chars_extracted(self):
        result = _extract_strings(bytes(range(256)))
        for s in result:
            assert all(0x20 <= ord(c) <= 0x7E for c in s)

    def test_no_duplicates(self):
        wide   = "Hello".encode("utf-16-le")
        result = _extract_strings(b"Hello\x00" + wide)
        assert result.count("Hello") == 1

    def test_custom_min_len_respected(self):
        assert "ABCDE" not in _extract_strings(b"ABCDE", min_len=6)

    def test_result_is_sorted(self):
        result = _extract_strings(b"zebra apple mango")
        assert result == sorted(result)


# ═══════════════════════════════════════════════════════════════════════════════
# TestParsePeImports
# ═══════════════════════════════════════════════════════════════════════════════

class TestParsePeImports:
    """PE import table parser — PE32/PE32+ architecture."""

    def test_empty_data_not_pe(self):
        assert _parse_pe_imports(b"")["is_pe"] is False

    def test_garbage_data_not_pe(self):
        assert _parse_pe_imports(b"\x00" * 256)["is_pe"] is False

    def test_mz_short_data_graceful(self):
        # Data shorter than 64 bytes (DOS header minimum) returns safely without crash.
        # is_pe stays False because the bounds check fires before the MZ check.
        result = _parse_pe_imports(b"MZ" + b"\x00" * 10)
        assert result["arch"]          == "unknown"
        assert result["mutex_apis"]    == []
        assert result["suspicious_apis"] == []

    def test_mz_invalid_pe_sig(self):
        data = bytearray(128)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"XX\x00\x00"   # wrong PE signature
        assert _parse_pe_imports(bytes(data))["arch"] == "unknown"

    def test_pe32_arch_detected(self):
        pe = _build_test_pe32()
        assert _parse_pe_imports(pe)["arch"] == "PE32"

    def test_pe32_dll_name_parsed(self):
        pe     = _build_test_pe32(["CreateMutexA"])
        result = _parse_pe_imports(pe)
        assert "kernel32.dll" in result["all_imports"]

    def test_pe32_mutex_apis_detected(self):
        pe     = _build_test_pe32(["CreateMutexA", "CreateMutexW", "SomeOther"])
        result = _parse_pe_imports(pe)
        assert "CreateMutexA" in result["mutex_apis"]
        assert "CreateMutexW" in result["mutex_apis"]
        assert "SomeOther"    not in result["mutex_apis"]

    def test_pe32_suspicious_api_detected(self):
        pe    = _build_test_pe32(["VirtualAllocEx"])
        names = {a["name"] for a in _parse_pe_imports(pe)["suspicious_apis"]}
        assert "VirtualAllocEx" in names

    def test_pe32_suspicious_api_fields(self):
        pe  = _build_test_pe32(["WriteProcessMemory"])
        api = _parse_pe_imports(pe)["suspicious_apis"][0]
        assert api["name"]     == "WriteProcessMemory"
        assert api["ttp"]      == "process_injection"
        assert api["severity"] == "high"

    def test_pe32_critical_suspicious_api(self):
        pe  = _build_test_pe32(["CreateRemoteThread"])
        api = _parse_pe_imports(pe)["suspicious_apis"][0]
        assert api["severity"] == "critical"
        assert api["ttp"]      == "process_injection"

    def test_pe32_no_functions_empty(self):
        pe     = _build_test_pe32(functions=[])
        result = _parse_pe_imports(pe)
        assert result["mutex_apis"]      == []
        assert result["suspicious_apis"] == []

    def test_pe32_clean_function_not_flagged(self):
        pe = _build_test_pe32(["GetSystemInfo", "HeapAlloc"])
        assert _parse_pe_imports(pe)["mutex_apis"] == []

    def test_truncated_pe_does_not_crash(self):
        pe     = _build_test_pe32(["CreateMutexA"])
        result = _parse_pe_imports(pe[:0x200])   # section data missing
        assert isinstance(result["is_pe"], bool)

    def test_mutex_apis_deduplicated(self):
        pe = _build_test_pe32(["CreateMutexA", "CreateMutexA"])
        assert _parse_pe_imports(pe)["mutex_apis"].count("CreateMutexA") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# TestClassifyMutexCandidate
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassifyMutexCandidate:
    """GUID / hex / known-malware classification."""

    def test_cobalt_strike_guid_known_match(self):
        result = _classify_mutex_candidate("{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}")
        assert result["is_guid"]    is True
        assert result["confidence"] == 0.95
        assert result["known_match"]["family"] == "Cobalt Strike Beacon"

    def test_plain_guid_no_known_match(self):
        result = _classify_mutex_candidate("{AABBCCDD-1234-5678-9ABC-DEF012345678}")
        assert result["is_guid"]     is True
        assert result["known_match"] is None
        assert result["confidence"]  == 0.70

    def test_hex_string_medium_confidence(self):
        result = _classify_mutex_candidate("a1b2c3d4e5f67890")   # 16 hex chars
        assert result["is_hex"]     is True
        assert result["confidence"] == 0.55

    def test_generic_string_low_confidence(self):
        result = _classify_mutex_candidate("My-Application-Mutex")
        assert result["confidence"] == 0.30
        assert result["known_match"] is None

    def test_wannacry_exact_match(self):
        result = _classify_mutex_candidate("WNcry@2ol7")
        assert result["known_match"]["family"]   == "WannaCry"
        assert result["known_match"]["severity"] == "critical"
        assert result["confidence"] == 0.95

    def test_wannacry_global_mutex(self):
        result = _classify_mutex_candidate("Global\\MsWinZonesCacheCounterMutexA")
        assert result["known_match"] is not None
        assert result["known_match"]["ttp"] == "ransomware"

    def test_darkcomet_prefix_match(self):
        result = _classify_mutex_candidate("DC_MUTEX-12345")
        assert result["known_match"]["family"] == "DarkComet RAT"
        assert result["known_match"]["ttp"]    == "rat"

    def test_nanocore_prefix_match(self):
        result = _classify_mutex_candidate("NANOCORE_INSTANCE_X")
        assert "NanoCore" in result["known_match"]["family"]

    def test_hex_too_short_not_hex(self):
        result = _classify_mutex_candidate("aabbccdd")   # 8 chars < 16
        assert result["is_hex"] is False

    def test_result_has_all_keys(self):
        result = _classify_mutex_candidate("Anything")
        assert set(result.keys()) == {"value", "is_guid", "is_hex", "confidence", "known_match"}

    def test_value_field_preserved(self):
        result = _classify_mutex_candidate("MyMutex-007")
        assert result["value"] == "MyMutex-007"


# ═══════════════════════════════════════════════════════════════════════════════
# TestExtractMutexCandidates
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtractMutexCandidates:
    """Candidate filtering and ranking."""

    def _no_mutex(self) -> dict:
        return {"is_pe": True, "arch": "PE32", "mutex_apis": [], "suspicious_apis": [], "all_imports": {}}

    def _with_mutex(self) -> dict:
        return {"is_pe": True, "arch": "PE32", "mutex_apis": ["CreateMutexA"], "suspicious_apis": [], "all_imports": {}}

    def test_empty_strings_returns_empty(self):
        assert _extract_mutex_candidates([], self._no_mutex()) == []

    def test_no_mutex_api_generic_strings_excluded(self):
        result = _extract_mutex_candidates(["NormalString", "AnotherWord"], self._no_mutex())
        assert result == []

    def test_no_mutex_api_guid_included(self):
        result = _extract_mutex_candidates(["{AABBCCDD-1234-5678-9ABC-DEF012345678}"], self._no_mutex())
        assert len(result) == 1 and result[0]["is_guid"] is True

    def test_no_mutex_api_hex_included(self):
        result = _extract_mutex_candidates(["a1b2c3d4e5f67890abcd1234567890ab"], self._no_mutex())
        assert len(result) == 1 and result[0]["is_hex"] is True

    def test_with_mutex_api_generic_included(self):
        result = _extract_mutex_candidates(["MyApp-Mutex", "SomeObj123"], self._with_mutex())
        assert len(result) == 2

    def test_known_malware_always_included(self):
        result = _extract_mutex_candidates(["WNcry@2ol7"], self._no_mutex())
        assert len(result) == 1 and result[0]["known_match"] is not None

    def test_cobalt_strike_always_included(self):
        result = _extract_mutex_candidates(
            ["{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}"], self._no_mutex()
        )
        assert len(result) == 1
        assert result[0]["known_match"]["family"] == "Cobalt Strike Beacon"

    def test_long_string_excluded(self):
        result = _extract_mutex_candidates(["A" * 129], self._with_mutex())
        assert result == []

    def test_dll_extension_excluded(self):
        result = _extract_mutex_candidates(["kernel32.dll", "user32.dll"], self._with_mutex())
        assert result == []

    def test_absolute_path_excluded(self):
        result = _extract_mutex_candidates(["C:\\Windows\\System32\\evil.exe"], self._with_mutex())
        assert result == []

    def test_sorted_by_confidence_descending(self):
        strings = [
            "WNcry@2ol7",
            "{AABBCCDD-1234-5678-9ABC-DEF012345678}",
            "somestring",
        ]
        result = _extract_mutex_candidates(strings, self._with_mutex())
        confs  = [c["confidence"] for c in result]
        assert confs == sorted(confs, reverse=True)

    def test_duplicates_deduplicated(self):
        strings = ["WNcry@2ol7", "WNcry@2ol7", "WNcry@2ol7"]
        result  = _extract_mutex_candidates(strings, self._no_mutex())
        assert len(result) == 1

    def test_api_names_excluded(self):
        result = _extract_mutex_candidates(["CreateMutexA", "OpenMutexW"], self._with_mutex())
        assert result == []

    def test_capped_at_50(self):
        strings = ["{" + str(_uuid.UUID(int=i)).upper() + "}" for i in range(60)]
        result  = _extract_mutex_candidates(strings, self._with_mutex())
        assert len(result) <= 50


# ═══════════════════════════════════════════════════════════════════════════════
# TestCalculateRiskScore
# ═══════════════════════════════════════════════════════════════════════════════

class TestCalculateRiskScore:
    """Risk score aggregation with mutex + import signals."""

    _H = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}

    def test_clean_text_zero_score(self):
        assert _calculate_risk_score(self._H, [], "Unknown (.txt)", "note.txt") == 0.0

    def test_suspicious_extension_adds_score(self):
        assert _calculate_risk_score(self._H, [], "Unknown (.exe)", "test.exe") > 0.0

    def test_pe_file_type_adds_score(self):
        assert _calculate_risk_score(self._H, [], "PE Executable (Windows)", "test.txt") > 0.0

    def test_critical_mutex_adds_040(self):
        candidates = [_classify_mutex_candidate("WNcry@2ol7")]
        score = _calculate_risk_score(self._H, [], "Unknown", "f.bin", mutex_candidates=candidates)
        assert score == pytest.approx(0.40, abs=0.001)

    def test_high_mutex_adds_025(self):
        candidates = [_classify_mutex_candidate("DCRAT_MUTEX")]
        score = _calculate_risk_score(self._H, [], "Unknown", "f.bin", mutex_candidates=candidates)
        assert score == pytest.approx(0.25, abs=0.001)

    def test_only_worst_mutex_counted(self):
        candidates = [
            _classify_mutex_candidate("WNcry@2ol7"),    # critical → 0.40
            _classify_mutex_candidate("MsMpEngMutex"),  # medium   → 0.15
        ]
        score = _calculate_risk_score(self._H, [], "Unknown", "f.bin", mutex_candidates=candidates)
        assert score == pytest.approx(0.40, abs=0.001)

    def test_unknown_mutex_no_contribution(self):
        candidates = [_classify_mutex_candidate("{AABBCCDD-1234-5678-9ABC-DEF012345678}")]
        score = _calculate_risk_score(self._H, [], "Unknown", "f.bin", mutex_candidates=candidates)
        assert score == 0.0   # plain GUID, no known match

    def test_suspicious_imports_capped_at_025(self):
        apis = [{"name": "CreateRemoteThread", "ttp": "pi", "severity": "critical"}] * 10
        score = _calculate_risk_score(self._H, [], "Unknown", "f.bin", suspicious_apis=apis)
        assert score <= 0.25 + 1e-6

    def test_signature_hits_contribute(self):
        hits  = [{"severity": "critical", "threat": "exploit"}]
        score = _calculate_risk_score(self._H, hits, "Unknown", "f.txt")
        assert score >= 0.40

    def test_double_extension_masquerade(self):
        score = _calculate_risk_score(self._H, [], "Unknown", "invoice.pdf.exe")
        assert score >= 0.20 + 0.25   # masquerade + suspicious ext

    def test_score_capped_at_1(self):
        hits = [{"severity": "critical", "threat": "x"}] * 10
        apis = [{"name": "CreateRemoteThread", "ttp": "pi", "severity": "critical"}] * 10
        candidates = [_classify_mutex_candidate("WNcry@2ol7")]
        score = _calculate_risk_score(
            self._H, hits, "PE Executable (Windows)", "evil.exe",
            mutex_candidates=candidates, suspicious_apis=apis,
        )
        assert score == 1.0


# ═══════════════════════════════════════════════════════════════════════════════
# TestAnalyzeArtifact  (async integration)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeArtifact:
    """Full pipeline — verify P7 fields present and correctly populated."""

    @pytest.mark.asyncio
    async def test_result_has_p7_fields(self):
        result = await analyze_artifact("note.txt", b"This is a clean text file.")
        for key in ("strings_count", "pe_analysis", "mutex_analysis", "suggested_iocs"):
            assert key in result

    @pytest.mark.asyncio
    async def test_strings_count_positive(self):
        result = await analyze_artifact("note.txt", b"Hello World Testing Four")
        assert result["strings_count"] > 0

    @pytest.mark.asyncio
    async def test_non_pe_pe_analysis_false(self):
        result = await analyze_artifact("note.txt", b"Plain text, no MZ header here.")
        assert result["pe_analysis"]["is_pe"] is False

    @pytest.mark.asyncio
    async def test_pe32_is_pe_true(self):
        pe     = _build_test_pe32(["CreateMutexA"])
        result = await analyze_artifact("sample.exe", pe)
        assert result["pe_analysis"]["is_pe"]  is True
        assert result["pe_analysis"]["arch"]   == "PE32"

    @pytest.mark.asyncio
    async def test_pe32_mutex_api_in_pe_analysis(self):
        pe     = _build_test_pe32(["CreateMutexA", "CreateMutexW"])
        result = await analyze_artifact("sample.exe", pe)
        assert "CreateMutexA" in result["pe_analysis"]["mutex_apis"]

    @pytest.mark.asyncio
    async def test_pe32_suspicious_api_in_pe_analysis(self):
        pe    = _build_test_pe32(["CreateRemoteThread"])
        result = await analyze_artifact("inject.exe", pe)
        names  = {a["name"] for a in result["pe_analysis"]["suspicious_apis"]}
        assert "CreateRemoteThread" in names

    @pytest.mark.asyncio
    async def test_wannacry_mutex_in_known_malware(self):
        data   = b"\x00" * 16 + b"WNcry@2ol7" + b"\x00" * 16
        result = await analyze_artifact("wanna.bin", data)
        families = [m["family"] for m in result["mutex_analysis"]["known_malware"]]
        assert "WannaCry" in families

    @pytest.mark.asyncio
    async def test_known_mutex_ttp_in_ttps(self):
        data   = b"\x00" * 8 + b"WNcry@2ol7" + b"\x00" * 8
        result = await analyze_artifact("wanna.bin", data)
        assert "ransomware" in result["ttps"]

    @pytest.mark.asyncio
    async def test_suggested_iocs_min_confidence(self):
        data   = b"\x00" * 8 + b"WNcry@2ol7" + b"\x00" * 8
        result = await analyze_artifact("wanna.bin", data)
        for ioc in result["suggested_iocs"]:
            assert ioc["confidence"] >= 0.55
            assert ioc["type"]       == "mutex"

    @pytest.mark.asyncio
    async def test_risk_elevated_by_known_mutex(self):
        # WannaCry mutex surrounded by null bytes so _extract_strings yields
        # it as an isolated token, enabling exact-match classification.
        clean = await analyze_artifact("clean.txt", b"Hello normal text here")
        evil  = await analyze_artifact("evil.bin",  b"\x00WNcry@2ol7\x00")
        assert evil["risk_score"] > clean["risk_score"]

    @pytest.mark.asyncio
    async def test_pe32_has_mutex_api_true(self):
        pe     = _build_test_pe32(["CreateMutexA"])
        result = await analyze_artifact("sample.exe", pe)
        assert result["mutex_analysis"]["has_mutex_api"] is True

    @pytest.mark.asyncio
    async def test_clean_pe_no_known_malware(self):
        pe     = _build_test_pe32(["GetSystemInfo"])
        result = await analyze_artifact("clean.exe", pe)
        assert result["mutex_analysis"]["known_malware"] == []

    @pytest.mark.asyncio
    async def test_cobalt_strike_guid_detected(self):
        guid   = b"{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}"
        result = await analyze_artifact("beacon.bin", b"\x00\x00" + guid + b"\x00\x00")
        families = [m["family"] for m in result["mutex_analysis"]["known_malware"]]
        assert "Cobalt Strike Beacon" in families


# ═══════════════════════════════════════════════════════════════════════════════
# TestAnalyzeFileAPI  (multipart upload — uses conftest client fixture)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeFileAPI:
    """POST /api/v1/analyze/file — requires analyst or admin role (TD1 fix)."""

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_403(self, client):
        """Security fix TD1: unauthenticated requests must be rejected."""
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("note.txt", b"test file content", "text/plain")},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_viewer_cannot_upload_file(self, client, viewer_headers):
        """Viewer role (read-only) must not be able to submit files for analysis."""
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("note.txt", b"test content", "text/plain")},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_can_upload_file(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("note.txt", b"This is a clean file.", "text/plain")},
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_p7_fields_in_response(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("note.txt", b"Clean text here please.", "text/plain")},
            headers=analyst_headers,
        )
        body = resp.json()
        for key in ("strings_count", "pe_analysis", "mutex_analysis", "suggested_iocs"):
            assert key in body, f"Missing P7 field '{key}' in API response"

    @pytest.mark.asyncio
    async def test_pe_file_pe_analysis_populated(self, client, analyst_headers):
        pe   = _build_test_pe32(["CreateMutexA", "VirtualAllocEx"])
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("sample.exe", pe, "application/octet-stream")},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["pe_analysis"]["is_pe"] is True
        assert body["pe_analysis"]["arch"]  == "PE32"

    @pytest.mark.asyncio
    async def test_wannacry_detected_via_api(self, client, analyst_headers):
        data = b"\x00" * 16 + b"WNcry@2ol7" + b"\x00" * 16
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("wanna.bin", data, "application/octet-stream")},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        families = [m["family"] for m in body["mutex_analysis"]["known_malware"]]
        assert "WannaCry" in families

    @pytest.mark.asyncio
    async def test_artifact_id_in_response(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("test.bin", b"test content here", "application/octet-stream")},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert "artifact_id" in resp.json()

    @pytest.mark.asyncio
    async def test_risk_score_in_response(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("test.txt", b"plain text file content", "text/plain")},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert "risk_score" in resp.json()


# ═══════════════════════════════════════════════════════════════════════════════
# TestAnalyzeDomainAPI  (regression — query param, not JSON body)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeDomainAPI:

    @pytest.mark.asyncio
    async def test_unauthenticated_domain_returns_403(self, client):
        resp = await client.post("/api/v1/analyze/domain", params={"domain": "google.com"})
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_clean_domain_clean_verdict(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/domain",
            params={"domain": "google.com"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "clean"

    @pytest.mark.asyncio
    async def test_suspicious_tld_flagged(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/domain",
            params={"domain": "malware-site.tk"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert "suspicious_tld" in resp.json()["flags"]

    @pytest.mark.asyncio
    async def test_dga_domain_suspicious(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/domain",
            params={"domain": "xkq7zrpmvwbad.xyz"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "suspicious"
        assert body["risk_score"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# TestAnalyzeIPAPI  (regression — query param, not JSON body)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeIPAPI:

    @pytest.mark.asyncio
    async def test_unauthenticated_ip_returns_403(self, client):
        resp = await client.post("/api/v1/analyze/ip", params={"ip": "192.168.1.1"})
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_private_ip_flagged(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/ip",
            params={"ip": "192.168.1.1"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert "private_ip" in resp.json()["flags"]

    @pytest.mark.asyncio
    async def test_loopback_flagged(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/ip",
            params={"ip": "127.0.0.1"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert "loopback" in resp.json()["flags"]

    @pytest.mark.asyncio
    async def test_invalid_ip_handled(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/analyze/ip",
            params={"ip": "not-an-ip"},
            headers=viewer_headers,
        )
        assert resp.status_code == 200
        assert "invalid_ip" in resp.json()["flags"]
