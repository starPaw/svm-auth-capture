import { RecoveryDomain } from "../../src/coordination.ts";
import { RestaurantOrders } from "../../src/restaurant.ts";
import { FileSubmissionJournal } from "../../src/submission-journal.ts";
const [raw,role,id,signature]=process.argv.slice(2),domain=new RecoveryDomain(JSON.parse(raw!));
let release!:()=>void;const gate=new Promise<void>(r=>{ release=r; });process.on("message",m=>{ if(m==="release") release(); });
process.send!("ready");
try {
  await domain.run("shared",async()=>{
    if(role === "order") {
      const orders=new RestaurantOrders(domain.metadata.members.find(m=>m.role === "orders")!.path,domain);
      const order=orders.read(id!);process.send!({ status:order.status });
      process.send!("entered");await gate;
      try { orders.reserve(id!,"beer");process.send!("unexpected-reservation"); } catch { process.send!("reservation-refused"); }
    } else {
      const journal=new FileSubmissionJournal(domain.metadata.members.find(m=>m.role === role)!.path,{ coordination:domain });
      journal.assertAccess();process.send!("entered");await gate;
      if(role === "facilitator") journal.resolve(signature!,{ result:"unresolved",recordedAt:"synthetic-race" });
    }
  },2000);
  process.send!("released");
} catch { process.send!("refused"); }
process.disconnect!();
