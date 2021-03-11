/**
 * @name NoAuth
 * @description Finds MVC actions configured to not have auth
 * @kind problem
 * @problem.severity warning
 * @precision high
 */

import csharp
import semmle.code.csharp.frameworks.system.web.Mvc

class AuthorizeAttribute extends Attribute {
    AuthorizeAttribute() {
        this.getType().hasName("AuthorizeAttribute")
    }
}

class AllowAnonymousAttribute extends Attribute {
    AllowAnonymousAttribute() {
        this.getType().hasName("AllowAnonymousAttribute")
    }
}

class ActionMethod extends Method {
    ActionMethod() {
        this.isPublic() and
        not this.isStatic() and
        this.getDeclaringType() instanceof Controller and
        not this.getDeclaringType().hasName("Controller") and
        not this.getAnAttribute() instanceof NonActionAttribute
    }
}

from ActionMethod a
where
    a.getAnAttribute() instanceof AllowAnonymousAttribute or 
    not exists( |
        a.getDeclaringType().getAnAttribute() instanceof AuthorizeAttribute
    )
    
select a, "Anonymous access allowed, check to validate these"
