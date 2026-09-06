package com.example.demo.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import com.example.demo.game.entity.ScoreLog;
import com.example.demo.school.entity.SchoolEntity;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Getter
@Setter
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "user_id", length = 50)
    private String userId;

    @Column(name = "character_name", nullable = true)
    private String charName;

    @Column(name = "image_url")
    private String imageUrl;

    @Column(name = "last_played")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastPlayed;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "password", nullable = false)
    @JsonIgnore
    private String password;

    @Column(name = "phone_number", nullable = false, unique = true, length = 13)
    private String phone;

    @Column(name = "register_date")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime registerDate;

    @Column(name = "total_lives")
    private int totalLives;

    @Column(name = "student_number", nullable = true)
    private String studentNumber;

    @ManyToOne
    @JoinColumn(name = "school_id")
    private SchoolEntity school;

    /** 누적 점수 (게임 + 오픈API 호출 등 모든 가산점) */
    @Column(name = "score", nullable = false)
    private Integer score = 0;

    @PrePersist
    public void onCreate() {
        if (this.password != null) {
            this.password = encryptPassword(this.password);
        }
        if (score == null) score = 0;
        if (registerDate == null) registerDate = LocalDateTime.now();
    }

    private String encryptPassword(String password) {
        return new BCryptPasswordEncoder().encode(password);
    }

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ScoreLog> scoreLogs = new ArrayList<>();

}
