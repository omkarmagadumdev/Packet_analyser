const { fiveTupleHash } = require("./types");

class LoadBalancer {
  constructor(lbId, fpList, fpStartId) {
    this.lbId = lbId;
    this.fpList = fpList;
    this.fpStartId = fpStartId;
    this.numFPs = fpList.length;

    this.packetsReceived = 0;
    this.packetsDispatched = 0;
    this.perFPCounts = new Array(this.numFPs).fill(0);
  }

  selectFP(tuple) {
    const hash = fiveTupleHash(tuple);
    return hash % this.numFPs;
  }

  dispatch(job) {
    this.packetsReceived += 1;
    const fpIndex = this.selectFP(job.tuple);
    this.fpList[fpIndex].process(job);
    this.packetsDispatched += 1;
    this.perFPCounts[fpIndex] += 1;
  }

  getStats() {
    return {
      packets_received: this.packetsReceived,
      packets_dispatched: this.packetsDispatched,
      per_fp_packets: [...this.perFPCounts]
    };
  }
}

class LBManager {
  constructor(numLBs, fpsPerLB, fpManager) {
    this.lbs = [];
    this.fpsPerLB = fpsPerLB;

    for (let lbId = 0; lbId < numLBs; lbId++) {
      const start = lbId * fpsPerLB;
      const fpList = [];
      for (let i = 0; i < fpsPerLB; i++) {
        fpList.push(fpManager.getFP(start + i));
      }
      this.lbs.push(new LoadBalancer(lbId, fpList, start));
    }
  }

  getLBForPacket(tuple) {
    const hash = fiveTupleHash(tuple);
    const index = hash % this.lbs.length;
    return this.lbs[index];
  }

  getAggregatedStats() {
    return this.lbs.reduce(
      (acc, lb) => {
        const stats = lb.getStats();
        acc.total_received += stats.packets_received;
        acc.total_dispatched += stats.packets_dispatched;
        return acc;
      },
      { total_received: 0, total_dispatched: 0 }
    );
  }
}

module.exports = {
  LoadBalancer,
  LBManager
};
