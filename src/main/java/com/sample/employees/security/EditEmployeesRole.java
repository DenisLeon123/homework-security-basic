package com.sample.employees.security;

import com.sample.employees.entity.Employee;
import io.jmix.security.model.EntityAttributePolicyAction;
import io.jmix.security.model.EntityPolicyAction;
import io.jmix.security.role.annotation.EntityAttributePolicy;
import io.jmix.security.role.annotation.EntityPolicy;
import io.jmix.security.role.annotation.ResourceRole;
import io.jmix.securityui.role.annotation.MenuPolicy;
import io.jmix.securityui.role.annotation.ScreenPolicy;

@ResourceRole(name = "editEmployees", code = "edit-employees")
public interface EditEmployeesRole {
    @EntityAttributePolicy(entityClass = Employee.class, attributes = "*", action = EntityAttributePolicyAction.MODIFY)
    @EntityPolicy(entityClass = Employee.class, actions = EntityPolicyAction.ALL)
    void employee();

    @MenuPolicy(menuIds = "Employee.browse")
    @ScreenPolicy(screenIds = {"Employee.browse", "Employee.edit"})
    void screens();
}