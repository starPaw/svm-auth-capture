import { RecoveryDomain, type DomainPaths } from "../../src/coordination.ts";
import { RestaurantOrders } from "../../src/restaurant.ts";
const [raw, mode, wait, id] = process.argv.slice(2);
const domain = new RecoveryDomain(JSON.parse(raw!) as DomainPaths);
let release!: () => void;
const gate = new Promise<void>(r => { release = r; });
process.on("message", m => { if (m === "release") release(); });
process.send!("ready");
try {
  await domain.run(mode as "shared" | "exclusive", async () => {
    if (mode === "shared") {
      const orders = new RestaurantOrders(domain.metadata.members.find(m => m.role === "orders")!.path, domain), orderId = id ?? "a".repeat(32);
      orders.reserve(orderId, "beer");
      orders.prepare({ id: orderId, events: [], status: "active" } as never, { action: "beer", status: "prepared", transactionBase64: "synthetic" } as never);
    }
    process.send!("entered");
    await gate;
  }, Number(wait));
  process.send!("released");
} catch { process.send!("refused"); }
process.disconnect!();
