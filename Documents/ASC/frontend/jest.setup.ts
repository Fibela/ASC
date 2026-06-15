import '@testing-library/jest-dom'

// Mock next/navigation for all tests
jest.mock('next/navigation', () => ({
  useRouter:   () => ({ replace: jest.fn(), push: jest.fn(), back: jest.fn() }),
  usePathname: () => '/',
}))

// Mock next/link
jest.mock('next/link', () => {
  const React = require('react')
  return function Link({ href, children, className }: any) {
    return React.createElement('a', { href, className }, children)
  }
})

// Silence unimportant console errors in tests
const originalError = console.error
beforeAll(() => {
  console.error = (...args: any[]) => {
    if (typeof args[0] === 'string' && args[0].includes('Warning:')) return
    originalError(...args)
  }
})
afterAll(() => {
  console.error = originalError
})
