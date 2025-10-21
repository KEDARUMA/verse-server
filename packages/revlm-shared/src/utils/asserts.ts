/**
 * Runtime assertion helpers used across packages.
 */

/**
 * Ensure a value is neither null nor undefined.
 * @param value - value to assert
 * @param message - optional error message used when throwing
 * @returns the asserted non-null/non-undefined value
 * @throws Error when value is null or undefined
 */
export function ensureDefined<T>(value: T | null | undefined, message?: string): T {
  if (value === null || value === undefined) {
    throw new Error(message ?? 'ensureDefined(): value is null or undefined');
  }
  return value;
}
