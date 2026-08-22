// Legacy iOS extra agent. The direct profile agent imports the same
// installer so feature behavior stays aligned between both launch paths.

import { ScriptConfig } from "./util";
import { installExtraHooks } from "./extra-hooks";

declare const rpc: any;
declare const send: any;

const conf = new ScriptConfig();
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

void installExtraHooks(conf, payload => send(payload));
