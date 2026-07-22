"""S108.2 (agente) — el communicator detecta hueco de conectividad y arma el reporte."""
from specter.communicator import SprecterComm


def _comm():
    # No toca red: solo probamos la lógica de _mark_reachable / pop_pending_gap.
    c = SprecterComm.__new__(SprecterComm)
    c._offline_since = None
    c._offline_ticks = 0
    c._pending_gap = None
    return c


def test_sin_hueco_no_reporta():
    c = _comm()
    c._mark_reachable(True)
    assert c.pop_pending_gap() is None


def test_hueco_y_recuperacion_genera_reporte():
    c = _comm()
    c._mark_reachable(False)   # tick 1 sin contacto
    c._mark_reachable(False)   # tick 2 sin contacto
    assert c.pop_pending_gap() is None      # aún offline, sin reporte
    c._mark_reachable(True)    # recupera contacto
    gap = c.pop_pending_gap()
    assert gap is not None
    assert gap["event_type"] == "specter.connectivity_gap"
    assert gap["ticks"] == 2
    assert "unreachable_from" in gap and "unreachable_to" in gap
    # se consume una sola vez
    assert c.pop_pending_gap() is None


def test_reachable_4xx_no_cuenta_como_offline():
    c = _comm()
    c._mark_reachable(True)    # respondió (aunque sea 4xx en el caller)
    assert c._offline_since is None and c.pop_pending_gap() is None
