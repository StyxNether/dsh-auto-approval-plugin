import { test } from "node:test";
import assert from "node:assert/strict";
import { apply } from "../lib/index.js";

/**
 * Minimal Cordis-like context: captures the `approval/request` listener and
 * the `inject` registrations, and serves a fake `permissionPresets` service.
 */
function createFakeContext(presets) {
  const listeners = new Map();
  const injections = [];
  return {
    listeners,
    injections,
    get(name) {
      if (name === "permissionPresets") return presets;
      return undefined;
    },
    on(event, handler, options) {
      listeners.set(event, { handler, options });
    },
    inject(services, callback) {
      injections.push({ services, callback });
      return () => {};
    },
    logger: { info() {}, warn() {} },
    effect() {}
  };
}

function config() {
  return {
    mode: "gated",
    trustedAreas: ["C:\\work"],
    harmlessPatterns: ["^ls(\\s|$)"],
    dangerousPatterns: ["\\bshutdown\\b"],
    maxCommandChars: 4000,
    logDecisions: true,
    trustedHosts: []
  };
}

function toolCallEvent(callId, name, argumentsText) {
  return { type: "tool/call", data: { callId, name, arguments: argumentsText } };
}

test("DSH 0.1.2-rc.1 shape: answerer reads snapshotEvents() and asks current(session)", () => {
  const events = [toolCallEvent("call-1", "bash", "{\"command\":\"ls\"}")];
  const session = {
    header: { cwd: "C:\\work" },
    // rc.1 removed `session.events`; the session is read through snapshotEvents().
    snapshotEvents() { return events; }
  };
  let currentArgument;
  const presets = {
    names: ["auto-approval", "workspace-write"],
    current(arg) {
      currentArgument = arg;
      assert.equal(Array.isArray(arg), false, "rc.1 current() must receive the session object");
      assert.equal(arg, session);
      return "auto-approval";
    }
  };
  const ctx = createFakeContext(presets);
  apply(ctx, config());

  const listener = ctx.listeners.get("approval/request");
  assert.ok(listener, "approval/request listener must be registered");
  const req = {
    agent: { session },
    callId: "call-1",
    toolName: "bash"
  };
  const outcome = listener.handler(req, () => "next");
  assert.equal(outcome, "allowed-once");
  assert.equal(currentArgument, session);
});

test("legacy rc.6 shape: answerer still accepts session.events and current(events)", () => {
  const events = [toolCallEvent("call-2", "bash", "{\"command\":\"ls\"}")];
  const session = {
    header: { cwd: "C:\\work" },
    // rc.6 exposed the raw log as `session.events`.
    events
  };
  const presets = {
    names: ["auto-approval", "workspace-write"],
    current(arg) {
      assert.equal(Array.isArray(arg), true, "legacy current() must receive the events array");
      return "auto-approval";
    }
  };
  const ctx = createFakeContext(presets);
  apply(ctx, config());

  const listener = ctx.listeners.get("approval/request");
  const req = {
    agent: { session },
    callId: "call-2",
    toolName: "bash"
  };
  const outcome = listener.handler(req, () => "next");
  assert.equal(outcome, "allowed-once");
});
