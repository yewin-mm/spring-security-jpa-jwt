package pers.yewin.springsecurityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pers.yewin.springsecurityjwt.model.entity.Role;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.repository
 */

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
