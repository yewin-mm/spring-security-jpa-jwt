package pers.yewin.springsecurityjwt;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import pers.yewin.springsecurityjwt.model.entity.Role;
import pers.yewin.springsecurityjwt.model.entity.Users;
import pers.yewin.springsecurityjwt.service.UserService;

import java.util.ArrayList;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt
 */

@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    // create password encoder with BCryptPasswordEncoder method
    // inject BCryptPasswordEncoder to passwordEncoder bean
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    // below code is automatically adding role and super admin account when application was started.
    // You can call create (register) user api for other new users by using super admin by postman.
    // You can also call create role api if you have idea for other role name. That will depend on your application logic
    // But if you add more roles, you need to add in Security Config class for permission (access) api.
    // You call add role to new user by calling add role to user api by postman.
    // In reality, adding user, role, role to user data will come from api from Frontend.
    // please comment out below code after running one time

    @Bean
    CommandLineRunner runner(UserService userService){
        return args -> {

          // creating some roles. You can add more if you want, or you can add by calling create role api later by postman.
          userService.saveRole(new Role(null, "SUPER_ADMIN"));
          userService.saveRole(new Role(null, "ADMIN"));
          userService.saveRole(new Role(null, "MANAGER"));
          userService.saveRole(new Role(null, "NORMAL_USER"));

          // create super admin account
          userService.saveUser(new Users(null, "Super Admin", "superadmin@gmail.com","superadmin", new ArrayList<>()));

          // adding role to suer admin user
          userService.addRoleToUser("superadmin@gmail.com", "SUPER_ADMIN");
          userService.addRoleToUser("superadmin@gmail.com", "ADMIN");
          userService.addRoleToUser("superadmin@gmail.com", "MANAGER");
          userService.addRoleToUser("superadmin@gmail.com", "NORMAL_USER");

            /**
             * after running one time in your machine, you can comment out above code (adding role and user and role to user),
             * if not so, some error log you may see in console as it's duplicate adding role and user, so, please comment out after running one time.
             * But if you deleted database, you need to un-comment above code to create first user by system and create roles.
             * Because if you want to do creating user or others, at least, you need one user to login and which user have access permission to create user, so it should have super admin role.
             * You can play (change, adding new) role name as you want.
             * But if you add more roles, you need to add in Security Config class too for permission (access) api.
              */




          // below is for testing purpose and system will automatically create some users and adding role to those users.
          // I prefer adding new users and role to user by calling api from postman by using above Super Admin account.

          /*
          userService.saveUser(new Users(null, "Ye", "ye@gmail.com","yeyeye", new ArrayList<>()));
          userService.saveUser(new Users(null, "Mg Mg", "mgmg@gmail.com","mgmg", new ArrayList<>()));
          userService.saveUser(new Users(null, "Aung Aung", "aungaung@gmail.com","aungaung", new ArrayList<>()));
          userService.saveUser(new Users(null, "Win", "win@gmail.com","winwin", new ArrayList<>()));
          userService.saveUser(new Users(null, "Ye Win", "yewin@gmail.com","yewin", new ArrayList<>()));
          userService.saveUser(new Users(null, "Mr. Ye Win", "mryewin@gmail.com","mryewin", new ArrayList<>()));

          // below is adding role to users for testing purpose

          userService.addRoleToUser("ye@gmail.com", "NORMAL_USER");

          userService.addRoleToUser("mgmg@gmail.com", "NORMAL_USER");
          userService.addRoleToUser("mgmg@gmail.com", "MANAGER");

          userService.addRoleToUser("aungaung@gmail.com", "MANAGER");
          userService.addRoleToUser("aungaung@gmail.com", "ADMIN");

          userService.addRoleToUser("win@gmail.com", "MANAGER");

          userService.addRoleToUser("yewin@gmail.com", "ADMIN");

          userService.addRoleToUser("mryewin@gmail.com", "SUPER_ADMIN");
          */

        };
    }

}
