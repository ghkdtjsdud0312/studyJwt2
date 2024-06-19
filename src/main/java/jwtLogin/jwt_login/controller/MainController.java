package jwtLogin.jwt_login.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class MainController {

    // 메인 페이지
    @GetMapping("/")
    public String mainP() {
        return "Main Controller";
    }

}
