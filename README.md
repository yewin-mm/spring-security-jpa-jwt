<!-- PROJECT SHIELDS -->

<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/yewin-mm/spring-security-jpa-jwt.svg?style=for-the-badge
[contributors-url]: https://github.com/yewin-mm/spring-security-jpa-jwt/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/yewin-mm/spring-security-jpa-jwt.svg?style=for-the-badge
[forks-url]: https://github.com/yewin-mm/spring-security-jpa-jwt/network/members
[stars-shield]: https://img.shields.io/github/stars/yewin-mm/spring-security-jpa-jwt.svg?style=for-the-badge
[stars-url]: https://github.com/yewin-mm/spring-security-jpa-jwt/stargazers
[issues-shield]: https://img.shields.io/github/issues/yewin-mm/spring-security-jpa-jwt.svg?style=for-the-badge
[issues-url]: https://github.com/yewin-mm/spring-security-jpa-jwt/issues
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/ye-win-1a33a292/
[product-screenshot]: images/screenshot.png


<h1 align="center">
  Overview
  <img src="https://github.com/yewin-mm/spring-security-jpa-jwt/blob/master/github/template/images/overview/Spring_Security_JPA_JWT.png" /><br/>
</h1>

# spring-security-jpa-jwt
* This is the sample backend microservice project for Spring Boot + Spring Security + Spring Data JPA + MySQL application.

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [About The Project](#about-the-project)
    - [Built With](#built-with)
- [Getting Started](#getting-started)
    - [Before you begin](#before-you-begin)
    - [Clone Project](#clone-project)
    - [Prerequisites](#prerequisites)
    - [Instruction](#instruction)
- [Contact Me](#contact)
- [Contributing](#Contributing)


<a name="about-the-project"></a>
## ⚡️About The Project
This is the sample backend microservice project for Spring Security, JWT (Access and Refresh Tokens) with Spring boot, Spring Security and Spring Data JPA.
You can learn how to secure your application with spring security and `role based authorization` for your every api endpoints by using spring security.


<a name="built-with"></a>
### 🪓 Built With
This project is built with
* [Java](https://www.oracle.com/au/java/technologies/javase/javase-jdk8-downloads.html)
* [Maven](https://maven.apache.org/download.cgi)
* [MySQL Database](https://www.postgresql.org/download/)


<a name="getting-started"></a>
## 🔥 Getting Started
This project is built with java, maven, mysql database and use `Project Lombok` as plugin.
So, please make sure all are installed in your machine.


<a name="before-you-begin"></a>
### 🔔 Before you begin
If you are new in Git, Github and new in Spring Boot configuration structure, <br>
You should see basic detail instructions first in here [Spring Boot Application Instruction](https://github.com/yewin-mm/spring-boot-app-instruction)<br>
If you are not good enough in basic JPA CRUD knowledge with Java Spring Boot, you should learn below example projects first. <br>
Click below links.
* [Spring Boot Sample CRUD Application](https://github.com/yewin-mm/spring-boot-sample-crud)


<a name="clone-project"></a>
### 🥡 Clone Project
* Clone the repo
   ```sh
   git clone https://github.com/yewin-mm/spring-security-jpa-jwt.git


<a name="prerequisites"></a>
### 🔑 Prerequisites
Prerequisites can be found in here [Spring Boot Application Instruction](https://github.com/yewin-mm/spring-boot-app-instruction).


<a name="instruction"></a>
### 📝 Instruction
* Change your database username and password in `application.properties`. 
* Here, if you use other Database like Postgres, You need to change that db connector dependency in `pom.xml` and change your db properties in `application.properties` file, you can check out here [Spring Boot Application Instruction](https://github.com/yewin-mm/spring-boot-app-instruction).
* Create your database inside your local Mysql database with name `spring_security_jwt` by running `create database spring_security_jwt`.
* Run the project in your IDE. Please make sure application was successfully running.
* You can check in your database is that there has 'User' and 'Role' table was auto created by application or not, under spring_security_jwt database by Database GUI tools like DBeaver.
* If you can't find, just click refresh in GUI and see again under spring_security_jwt database.

* Import `spring-security-jpa-jwt.postman_collection.json` file under project directory (see that file in project directory) into your installed Postman application.
    * Click in your Postman (top left corner) import -> file -> upload files -> {choose that json file} and open/import.
    * After that, you can see the folder which you import from file in your Postman.
* Now, you can 'Test' this project by calling API from Postman. Or you can call it from your frontend application.
    * Open your imported folder in postman and inside this folder, you will see total of 7 API requests and you can test it all by clicking `Send` button and see the response.
    * Firstly, call the login api in postman with username `superadmin@gmail.com` and password `superadmin` under `x-www-form-urlencoded` under `Body` tab.
    * That username and password will automatically create after application was run, you can check in `SpringSecurityJwtApplication` class.
    * If you stop and re-run application, please comment out that auto create user code for superadmin user (in `SpringSecurityJwtApplication` class) as that is already insert in your database. (But if you delete your local database, you need to open that code for one time)
    * If you get `access-token` and `refresh-token` from login response, you can call other apis by adding that `access-token` value in header. (If you don't add that, you can't call the other apis)
    * You can create another users by calling `Create User` api for testing, you need to give role to that user to get permission to call to other api from that user by calling add role to user api.
    * There were total of 4 role in the system (SUPER_ADMIN, ADMIN, MANAGER, NORMAL_USER), for the roles you can reference role table.
    * If your token was expired, you need to call token/refresh api by adding `refresh-token` value in header.
    * You can login with new user that you created and already assign role to that user, and you can use that user's `access-token` to call other apis.
    * You can also check for whether user who has `normal user` role can call `Create User` api or not by adding that user `access-token` in header.
    * You can check data in database too (user and role table) by DBeaver tools, or other db tools, or you can manually select query in your database console)

* After that you can see the code and check the code which you don't know. You can learn it and you can apply in your job or study fields.
* Please note that updated spring security dependency is deprecated for WebSecurityConfigurerAdapter. So, please don't do update spring security dependency version in `pom.xml`.

***Have Fun and Enjoy in Learning Code***


<a name="contact"></a>
## ✉️ Contact
Name - Ye Win <br> LinkedIn profile -  [Ye Win's LinkedIn](https://www.linkedin.com/in/ye-win-1a33a292/)  <br> Email Address - yewin.mmr@gmail.com

Project Link: [Spring Security JPA JWT Demo Application](https://github.com/yewin-mm/spring-security-jpa-jwt)


<a name="contributing"></a>
## ⭐ Contributing
Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.
<br>If you want to contribute....
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/yourname`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push -u origin feature/yourname`)
5. Open a Pull Request


