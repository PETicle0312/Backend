package com.example.demo.user.service;

import com.example.demo.user.dto.*;
import com.example.demo.user.entity.User;
import com.example.demo.school.entity.SchoolEntity;
import com.example.demo.school.repository.SchoolRepository;
import com.example.demo.user.repository.UserRepository;
import com.example.demo.device.repository.*;
import com.example.demo.game.repository.RankingRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final SchoolRepository schoolRepository;
    private final PetInputLogRepository petInputLogRepository;
    private final RankingRepository rankingRepository;

    @Override
    public boolean existsByUserId(String userId) {
        return userRepository.existsByUserId(userId);
    }

    @Override
    @Transactional
    public String registerUser(UserRegisterDto dto) {
        if (dto.getSchoolId() == null || dto.getSchoolId().trim().isEmpty()) {
            return "학교를 선택해 주세요.";
        }

        Long schoolId;
        try {
            schoolId = Long.parseLong(dto.getSchoolId());
        } catch (NumberFormatException e) {
            return "올바른 학교 ID 형식이 아닙니다.";
        }

        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            return "비밀번호가 일치하지 않습니다.";
        }

        if (userRepository.existsByUserId(dto.getUserId())) {
            return "중복된 아이디입니다.";
        }

        SchoolEntity school = schoolRepository.findById(schoolId)
                .orElseThrow(() -> new IllegalArgumentException("해당 학교가 존재하지 않습니다."));

        User user = new User(
                dto.getUserId(), // userId
                dto.getCharName(), // charName
                dto.getImageUrl(), // imageUrl
                null, // lastPlayed
                dto.getName(), // name
                dto.getPassword(), // password
                dto.getPhone(), // phone
                LocalDateTime.now(), // registerDate
                3, // totalLives
                dto.getStudentNumber(), // studentNumber
                school // school
, null, null
        );

        userRepository.save(user);
        log.info("회원가입을 완료했습니다.");

        return "회원가입 성공";
    }

    @Override
    public List<UserRankingDto> getUserRanking() {
        return null;
    }

    @Override
    public void startGameSession(StartSessionDto dto) {
    }

    @Override
    public boolean checkUserIdDuplicate(String userId) {
        return userRepository.existsByUserId(userId);
    }

}
