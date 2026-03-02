/**
 * @module tools/payments-send
 * @description Defines the `payments.send` tool that agents can invoke to
 * submit policy-enforced payment requests through the ClawSight platform.
 * The tool validates inputs, emits telemetry for both the request and the
 * result, and translates platform responses (submitted / blocked / error)
 * into appropriate success or error outcomes for the caller.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { jsonResult } from "openclaw/plugin-sdk";
import crypto from "node:crypto";
import { getRuntime } from "../runtime.js";

/**
 * JSON Schema definition for the `payments.send` tool parameters.
 * Requires `toAddress` and `amount`; all other fields are optional.
 */
const paymentSendParameters = {
  type: "object",
  additionalProperties: false,
  required: ["toAddress", "amount"],
  properties: {
    toAddress: {
      type: "string",
      description: "Destination address.",
    },
    amount: {
      type: "string",
      description: "Amount (string to avoid float issues).",
    },
    chain: {
      type: "string",
      description: "Chain/network identifier (optional).",
    },
    asset: {
      type: "string",
      description: "Asset/currency ticker (optional).",
    },
    memo: {
      type: "string",
      description: "Memo/description (optional).",
    },
    idempotencyKey: {
      type: "string",
      description: "Idempotency key for safe retries (optional).",
    },
  },
};

/**
 * @description Factory function that creates the `payments.send` tool
 * definition, including its JSON Schema, metadata, and async `execute`
 * handler. The returned tool object is intended to be registered with the
 * OpenClaw plugin SDK.
 *
 * The execute handler:
 * 1. Retrieves the active ClawSight runtime.
 * 2. Validates required `toAddress` and `amount` parameters.
 * 3. Emits a "payment/send" telemetry event before dispatching the request.
 * 4. Calls the platform's `paymentsSend` endpoint.
 * 5. Emits a "payment/send_result" telemetry event with the outcome.
 * 6. Throws on "blocked" or "error" responses; returns the result on success.
 *
 * @param _api - The OpenClaw plugin API (reserved for future use).
 * @returns A tool descriptor object with `name`, `label`, `description`,
 *   `parameters`, and `execute` members.
 */
export function createPaymentsSendTool(_api: OpenClawPluginApi) {
  return {
    name: "payments.send",
    label: "Payments Send (ClawSight)",
    description:
      "Send a payment via the ClawSight platform (policy-enforced: allow/deny lists, caps, approvals). The agent never receives wallet private keys.",
    parameters: paymentSendParameters,
    async execute(_toolCallId: string, params: Record<string, unknown>) {
      const rt = getRuntime();
      if (!rt) {
        throw new Error("clawsight runtime not initialized");
      }
      const toAddress = typeof params.toAddress === "string" ? params.toAddress.trim() : "";
      if (!toAddress) {
        throw new Error("toAddress required");
      }
      const amount = typeof params.amount === "string" ? params.amount.trim() : "";
      if (!amount) {
        throw new Error("amount required");
      }

      const req = {
        chain: typeof params.chain === "string" ? params.chain.trim() : undefined,
        asset: typeof params.asset === "string" ? params.asset.trim() : undefined,
        toAddress,
        amount,
        memo: typeof params.memo === "string" ? params.memo.trim() : undefined,
        idempotencyKey:
          typeof params.idempotencyKey === "string" ? params.idempotencyKey.trim() : undefined,
      };
      const requestId = crypto.randomUUID();
      const startedAt = Date.now();

      rt.emit({
        category: "payment",
        action: "send",
        severity: "debug",
        requestId,
        payload: { ...req, amount: req.amount, toAddress: req.toAddress },
      });

      const res = await rt.paymentsSend(req);

      rt.emit({
        category: "payment",
        action: "send_result",
        severity: res.status === "blocked" ? "warn" : res.status === "submitted" ? "info" : "error",
        requestId,
        durationMs: Date.now() - startedAt,
        result: res.status === "submitted" ? "ok" : res.status === "blocked" ? "blocked" : "error",
        payload: {
          ...res,
          chain: req.chain,
          asset: req.asset,
          amount: req.amount,
          toAddress: req.toAddress,
        },
      });

      if (res.status === "blocked") {
        throw new Error(res.reason ? `payment blocked: ${res.reason}` : "payment blocked by policy");
      }
      if (res.status === "error") {
        throw new Error(res.reason ? `payment failed: ${res.reason}` : "payment failed");
      }

      return jsonResult(res);
    },
  };
}
