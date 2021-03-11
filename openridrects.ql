/**
 * @name Finds some OpenRedirects
 * @description Finds MVC actions where user controlled data flows into a RedirectCall
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 */


import csharp
import DataFlow::PathGraph
import semmle.code.csharp.security.dataflow.flowsources.Remote

class RedirectCall extends MethodCall {
    RedirectCall() {
        this.getTarget().hasName("Redirect")
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "OpenRedirect" }

    override predicate isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(RedirectCall rc | 
            rc.getAnArgument() = sink.asExpr()
        )
    }

    override predicate isSanitizer(DataFlow::Node node) { 
        exists(MethodCall mc, SelectionStmt s |            
            mc.getTarget().hasName("IsLocalUrl") and
            s.getCondition() = mc and
            mc.getAnArgument() = node.asExpr()            
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "$@ flows to Redirect call, this is usually bad.", source.getNode(),
  "User-provided data"