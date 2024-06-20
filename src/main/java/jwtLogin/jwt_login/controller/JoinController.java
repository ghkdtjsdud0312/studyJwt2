package jwtLogin.jwt_login.controller;

import jwtLogin.jwt_login.dto.JoinDTO;
import jwtLogin.jwt_login.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    // service 주입 받기
    private final JoinService joinService;

    // controller의 생성자 방식으로 joinService를 주입 받는다.
    private JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    // 회원가입
    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {
        joinService.joinProcess(joinDTO);
        return "ok";
    }

}
