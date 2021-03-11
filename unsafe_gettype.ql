/**
 * @name Determining types from user controlled data
 * @description Calling GetType with untrusted data usually leads to problems
 * @kind path-problem
 * @problem.severity error
 * @precision high
 */

import csharp
import DataFlow::PathGraph
import semmle.code.csharp.security.dataflow.flowsources.Remote

class LoadCall extends MethodCall {
  LoadCall() {
    this.getTarget().getQualifiedName() = "System.Xml.XmlDocument.Load"
  }
}

class GetTypeCall extends MethodCall {
  GetTypeCall() {
    this.getTarget().getQualifiedName() = "System.Type.GetType"
  }
}

class GetAttributeCall extends MethodCall {
  GetAttributeCall() {
    this.getTarget().getQualifiedName() = "System.Xml.XmlElement.GetAttribute"
  }
}

class TaintTrackingConfig extends TaintTracking::Configuration {
  TaintTrackingConfig() { this = "UserControlledType" }

  override predicate isSource(DataFlow::Node source) {
    exists(LoadCall lc, RemoteFlowSource fs |
      source.asExpr() = lc.getQualifier() and
      lc.getAnArgument() = fs.asExpr()
    )
  }
  override predicate isSink(DataFlow::Node sink) {
    exists (GetTypeCall gc |
      gc.getAnArgument() = sink.asExpr()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(GetAttributeCall ga |
      n1.asExpr() = ga.getQualifier() and
      n2.asExpr() = ga
    )
  }
}

from TaintTrackingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source, source, sink, "$@ flows to GetType call, this is usually bad.", source.getNode(),
  "User-provided data"



