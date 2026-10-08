// Exercise the committed production bundle's receiver, never a reimplemented message guard.
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { getBase64Encoder, getBase58Encoder, getBase58Decoder, getTransactionDecoder, partiallySignTransaction } from "@solana/kit";
import { createHarness, type Harness } from "./fixture.js";
import { demoComputeInstructions } from "../src/demo-compute.js";
import { encodeTransaction } from "../src/transactions.js";

const trustedOrigin = "https://connect.solflare.com";
type Frame = { isConnected: boolean; style: Record<string,string>; contentWindow: { postMessage: ReturnType<typeof vi.fn> } | null };
let h: Harness, events: EventTarget, frames: Frame[], sdk: any, bundle: any;
beforeEach(async () => {
  h = await createHarness(); frames = []; events = new EventTarget();
  vi.stubGlobal("window", Object.assign(events, { location: { origin: "https://capture402.xyz" } }));
  vi.stubGlobal("document", { title: "Capture402", getElementsByClassName: () => [], body: { appendChild() {} }, createElement: () => {
    const frame: Frame = { isConnected: true, style: {}, contentWindow: { postMessage: vi.fn() } }; frames.push(frame);
    return { className: "", innerHTML: "", querySelector: () => frame, remove() { frame.isConnected = false; } };
  } });
  vi.stubGlobal("localStorage", { getItem: () => null, setItem() {}, removeItem() {} });
  const path = "../web/solflare.js"; bundle = await import(path); sdk = bundle.createSolflareDevnet();
});
afterEach(async () => { if (frames.length) inject({ type: "event", event: { type: "disconnect" } }); sdk?._disconnected(); vi.unstubAllGlobals(); await h.close(); });
const current = () => frames.at(-1)!;
// Node's MessageEvent only accepts its own MessagePort as source. These DOM event fixtures
// carry the exact stub iframe WindowProxy identity and go through the real window listener.
function inject(data: unknown, ...sender: [unknown?, unknown?]) {
  const origin = sender.length > 0 ? sender[0] : trustedOrigin;
  const source = sender.length > 1 ? sender[1] : current().contentWindow;
  const event = new Event("message"); Object.assign(event, { origin, source, data: { channel: "solflareIframeToWalletAdapter", data } });
  events.dispatchEvent(event);
}
const connectMessage = (publicKey: string) => ({ type: "event", event: { type: "connect", data: { publicKey } } });
async function connected() {
  const promise = sdk.connect(); inject(connectMessage(h.payer.address)); await promise;
  expect(sdk.publicKey.toBase58()).toBe(h.payer.address);
}
const invalidSenders = ["missing-origin", "null-origin", "foreign-origin", "lookalike-origin", "missing-source", "null-source", "same-origin-wrong-window", "foreign-origin-trusted-window", "stale-window"] as const;
function sender(kind: typeof invalidSenders[number]) {
  const source = current().contentWindow;
  switch (kind) {
    case "missing-origin": return { origin: undefined, source };
    case "null-origin": return { origin: "null", source };
    case "foreign-origin": return { origin: "https://attacker.invalid", source: {} };
    case "lookalike-origin": return { origin: `${trustedOrigin}.attacker.invalid`, source };
    case "missing-source": return { origin: trustedOrigin, source: undefined };
    case "null-source": return { origin: trustedOrigin, source: null };
    case "same-origin-wrong-window": return { origin: trustedOrigin, source: {} };
    case "foreign-origin-trusted-window": return { origin: "https://attacker.invalid", source };
    case "stale-window": sdk._injectElement(); return { origin: trustedOrigin, source };
  }
}
test.each(invalidSenders)("%s cannot connect, change accounts, disconnect, resize or resolve a request", async kind => {
  const connecting = sdk.connect(); const untrusted = sender(kind);
  const send = (data: unknown) => inject(data, untrusted.origin, untrusted.source);
  const onConnect = vi.fn(), onChange = vi.fn(), onDisconnect = vi.fn();
  sdk.on("connect", onConnect); sdk.on("accountChanged", onChange); sdk.on("disconnect", onDisconnect);
  send(connectMessage(h.outsider.address)); expect(onConnect).not.toHaveBeenCalled(); expect(sdk.publicKey).toBeNull();
  inject(connectMessage(h.payer.address)); await connecting; expect(onConnect).toHaveBeenCalledTimes(1);
  send({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } });
  send({ type: "event", event: { type: "disconnect" } });
  send({ type: "event", event: { type: "collapse" } });
  expect(sdk.publicKey.toBase58()).toBe(h.payer.address); expect(sdk.connected).toBe(true);
  expect(onChange).not.toHaveBeenCalled(); expect(onDisconnect).not.toHaveBeenCalled();
  const style = { ...current().style };
  send({ type: "resize", resizeMode: "full", params: { mode: "fullscreen" } });
  send({ type: "resize", resizeMode: "coordinates", params: { width: 999, height: 999 } });
  expect(current().style).toEqual(style);
  // A real SDK adapter request must stay pending despite forged success AND error responses.
  const request = sdk._adapterInstance._sendMessage({ method: "signTransaction", params: {} });
  const id = current().contentWindow!.postMessage.mock.calls.at(-1)![0].data.id;
  const resolved = vi.fn(), rejected = vi.fn(); request.then(resolved, rejected);
  send({ type: "response", id, result: "attacker-controlled" });
  send({ type: "response", id, error: "attacker-controlled" });
  await Promise.resolve(); expect(resolved).not.toHaveBeenCalled(); expect(rejected).not.toHaveBeenCalled();
  inject({ type: "response", id, result: "trusted-result" }); await expect(request).resolves.toBe("trusted-result");
});
test("original P2-2 forged MessageEvent cannot establish the bundled SDK connection", async () => {
  const changed = vi.fn(), connected = vi.fn(); const promise = bundle.connectSolflareDevnet(changed); promise.then(connected);
  events.dispatchEvent(new MessageEvent("message", { origin: "https://attacker.invalid", source: null, data: { channel: "solflareIframeToWalletAdapter", data: connectMessage(h.outsider.address) } }));
  await Promise.resolve(); expect(connected).not.toHaveBeenCalled(); expect(changed).not.toHaveBeenCalled();
  inject(connectMessage(h.payer.address)); const connection = await promise; expect(connection.account.address).toBe(h.payer.address);
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } }, "https://attacker.invalid", null);
  inject({ type: "event", event: { type: "disconnect" } }, "https://attacker.invalid", null);
  expect(changed).not.toHaveBeenCalled();
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } });
  expect(changed).toHaveBeenLastCalledWith(expect.objectContaining({ address: h.outsider.address }));
  inject({ type: "event", event: { type: "disconnect" } }); expect(changed).toHaveBeenLastCalledWith(null);
  connection.off();
});
test("trusted connect/accountChanged/disconnect and full/coordinate resize messages continue to work", async () => {
  await connected();
  const changed = vi.fn(), disconnected = vi.fn(); sdk.on("accountChanged", changed); sdk.on("disconnect", disconnected);
  inject({ type: "resize", resizeMode: "full", params: { mode: "fullscreen" } }); expect(current().style.width).toBe("100%");
  inject({ type: "resize", resizeMode: "coordinates", params: { width: 300, height: 200, top: 10, left: 20 } });
  expect(current().style).toMatchObject({ width: "300px", height: "200px", top: "10px", left: "20px" });
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } });
  expect(changed).toHaveBeenCalledTimes(1); expect(sdk.publicKey.toBase58()).toBe(h.outsider.address);
  inject({ type: "event", event: { type: "disconnect" } }); expect(disconnected).toHaveBeenCalledTimes(1); expect(sdk.publicKey).toBeNull();
});
test("removed, absent or windowless iframe is never trusted and rejected payloads are not inspected", async () => {
  await connected(); const frame = current(), windowSource = frame.contentWindow;
  const accountChanged = vi.fn(); sdk.on("accountChanged", accountChanged);
  const hostile = new Event("message"); Object.defineProperties(hostile, {
    origin: { value: "https://attacker.invalid" }, source: { value: windowSource },
    data: { get() { throw new Error("rejected sender payload must not be inspected"); } },
  });
  events.dispatchEvent(hostile);
  // Another SDK instance or DOM teardown may remove a frame without clearing this
  // instance's references. Its WindowProxy identity alone must not retain trust.
  frame.isConnected = false;
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } });
  frame.isConnected = true;
  frame.contentWindow = null;
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } }, trustedOrigin, null);
  frame.contentWindow = windowSource; sdk._removeElement(); expect(sdk._iframe).toBeNull();
  inject({ type: "event", event: { type: "accountChanged", data: { publicKey: h.outsider.address } } }, trustedOrigin, windowSource);
  expect(accountChanged).not.toHaveBeenCalled(); expect(sdk.publicKey.toBase58()).toBe(h.payer.address);
});
test("trusted signing response retains Devnet, exact message and payer-only signature checks in the actual bundle", async () => {
  const standardPath = "../web/wallet.js"; const standard = await import(standardPath);
  const promise = bundle.connectSolflareDevnet(() => {}); inject(connectMessage(h.payer.address)); const connection = await promise;
  const unsigned = encodeTransaction(await h.signedAuthorize({ salt: h.newSalt(), signers: [], extra: demoComputeInstructions(200_000) }));
  async function respond(signers: typeof h.payer[], mutate = false) {
    const request = current().contentWindow!.postMessage.mock.calls.at(-1)![0].data;
    const wire = new Uint8Array(getBase58Encoder().encode(request.params.transaction));
    if (mutate) wire[wire.length - 1]! ^= 1;
    const tx = getTransactionDecoder().decode(wire);
    const signed = await partiallySignTransaction(signers.map(s => s.keyPair), tx);
    inject({ type: "response", id: request.id, result: getBase58Decoder().decode(getBase64Encoder().encode(encodeTransaction(signed))) });
  }
  const signing = standard.walletSign(connection, unsigned, standard.DEVNET_POLICY);
  // walletSign awaits hashing the comparison baseline before calling the SDK.
  await vi.waitFor(() => expect(current().contentWindow!.postMessage).toHaveBeenCalled());
  await respond([h.payer]); await signing;
  expect(standard.signingReport()).toMatchObject({ messageEqual: true, changedSignatureSlots: [{ signer: h.payer.address }] });
  current().contentWindow!.postMessage.mockClear();
  const extraSigner = standard.walletSign(connection, unsigned, standard.DEVNET_POLICY);
  const refused = expect(extraSigner).rejects.toThrow("only the payer signature");
  await vi.waitFor(() => expect(current().contentWindow!.postMessage).toHaveBeenCalled());
  await respond([h.payer, h.facilitatorKey]); await refused;
  current().contentWindow!.postMessage.mockClear();
  const alteredMessage = standard.walletSign(connection, unsigned, standard.DEVNET_POLICY);
  const messageRefused = expect(alteredMessage).rejects.toThrow("Wallet changed the offered transaction");
  await vi.waitFor(() => expect(current().contentWindow!.postMessage).toHaveBeenCalled());
  await respond([h.payer], true); await messageRefused;
  expect(standard.signingReport().messageEqual).toBe(false);
  expect(h.ledger.submissions).toHaveLength(0); connection.off();
});
