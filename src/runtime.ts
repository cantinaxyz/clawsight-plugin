/**
 * @module runtime
 * @description Singleton accessor for the ClawSight runtime instance. Provides
 * global get/set functions so that any module in the plugin can retrieve the
 * active runtime without passing it explicitly through every call site.
 */

import type { ClawsightRuntime } from "./service-types.js";

let runtime: ClawsightRuntime | null = null;

/**
 * @description Replaces the current global ClawSight runtime reference.
 * Pass `null` to clear the runtime (e.g. during shutdown).
 * @param next - The new runtime instance to store, or `null` to clear it.
 */
export function setRuntime(next: ClawsightRuntime | null) {
  runtime = next;
}

/**
 * @description Returns the current global ClawSight runtime instance,
 * or `null` if the plugin has not been initialised yet (or has been shut down).
 * @returns The active {@link ClawsightRuntime} or `null`.
 */
export function getRuntime(): ClawsightRuntime | null {
  return runtime;
}

