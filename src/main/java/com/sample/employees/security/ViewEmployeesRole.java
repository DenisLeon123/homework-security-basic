package com.sample.employees.security;

import com.sample.employees.entity.Employee;
import io.jmix.security.model.EntityAttributePolicyAction;
import io.jmix.security.model.EntityPolicyAction;
import io.jmix.security.role.annotation.EntityAttributePolicy;
import io.jmix.security.role.annotation.EntityPolicy;
import io.jmix.security.role.annotation.ResourceRole;
import io.jmix.securityui.role.annotation.MenuPolicy;
import io.jmix.securityui.role.annotation.ScreenPolicy;

@ResourceRole(name = "viewEmployees", code = "view-employees")
public interface ViewEmployeesRole {
    @EntityAttributePolicy(entityClass = Employee.class, attributes = "*", action = EntityAttributePolicyAction.VIEW)
    @EntityPolicy(entityClass = Employee.class, actions = EntityPolicyAction.READ)
    void employee();

    @MenuPolicy(menuIds = "Employee.browse")
    @ScreenPolicy(screenIds = {"Employee.browse", "Employee.edit"})
    void screens();
}