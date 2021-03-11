/**
 * @name NoCSRF
 * @description Finds MVC actions without CSRF
 * @kind problem
 * @problem.severity warning
 * @precision high
 */

import csharp
import semmle.code.csharp.frameworks.system.web.Mvc


class DangerousAttributes extends SystemWebMvcAttribute {
    DangerousAttributes() {
        this.getType().hasName("HttpPostAttribute") or
        this.getType().hasName("HttpPutAttribute") or
        this.getType().hasName("HttpDeleteAttribute")
    }
}

class DangerouseActionMethod extends Method {
    DangerouseActionMethod() {
        this.isPublic() and
        not this.isStatic() and
        not this.getAnAttribute() instanceof NonActionAttribute and
        this.getDeclaringType() instanceof Controller and
        not this.getDeclaringType().hasName("Controller") and
        this.getAnAttribute() instanceof DangerousAttributes
    }
}

from DangerouseActionMethod a
where not a.getAnAttribute() instanceof ValidateAntiForgeryTokenAttribute
select a

