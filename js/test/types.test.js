const test = require("node:test");
const assert = require("node:assert/strict");

const jsTypes = require("../src/types");
const webTypes = require("../../web/scripts/engine/types");

function buildExpectations(typesModule) {
  return [
    ["www.microsoft.com", typesModule.AppType.MICROSOFT],
    ["www.netflix.com", typesModule.AppType.NETFLIX],
    ["x.com", typesModule.AppType.TWITTER],
    ["t.co", typesModule.AppType.TWITTER],
    ["www.youtube.com", typesModule.AppType.YOUTUBE]
  ];
}

for (const [label, typesModule] of [
  ["js", jsTypes],
  ["web", webTypes]
]) {
  test(`${label} sniToAppType classifies boundary-sensitive hostnames correctly`, () => {
    for (const [hostname, expected] of buildExpectations(typesModule)) {
      assert.equal(typesModule.sniToAppType(hostname), expected, `${label} misclassified ${hostname}`);
    }
  });
}
