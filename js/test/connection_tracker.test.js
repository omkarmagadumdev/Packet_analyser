const test = require("node:test");
const assert = require("node:assert/strict");

const jsTracker = require("../src/connection_tracker");
const jsTypes = require("../src/types");
const webTracker = require("../../web/scripts/engine/connection_tracker");

const clientTuple = {
  src_ip: 1,
  dst_ip: 2,
  src_port: 12345,
  dst_port: 443,
  protocol: 6
};

const serverTuple = jsTypes.reverseTuple(clientTuple);

for (const [label, trackerModule] of [
  ["js", jsTracker],
  ["web", webTracker]
]) {
  test(`${label} connection tracker reuses the same connection for reverse-direction packets`, () => {
    const tracker = new trackerModule.ConnectionTracker(0);
    const outbound = tracker.getOrCreateConnection(clientTuple);
    const inbound = tracker.getOrCreateConnection(serverTuple);

    assert.equal(inbound, outbound);
    assert.equal(tracker.getActiveCount(), 1);
  });
}
