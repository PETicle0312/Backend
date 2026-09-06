package com.example.demo.school.service;

import com.example.demo.school.dto.SchoolSearchResponseDto;
import com.example.demo.school.dto.StudentVerifyDto;
import com.example.demo.school.entity.SchoolEntity;
import com.example.demo.school.repository.SchoolRepository;
import com.example.demo.school.repository.SchoolStudentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.json.JSONArray;
import org.json.JSONObject;

@Service
@Slf4j
@RequiredArgsConstructor
public class SchoolServiceImpl implements SchoolService {

    private final SchoolRepository schoolRepository;
    private final SchoolStudentRepository studentRepository;
    private final RestTemplate restTemplate;

    @org.springframework.beans.factory.annotation.Value("${neis.api-key:}")
    private String neisApiKey;
    

    @Override
    public List<String> searchSchool(String keyword) {
        return schoolRepository.findBySchoolNameContaining(keyword)
                .stream()
                .map(s -> s.getSchoolName())
                .collect(Collectors.toList());
    }

    @Override
    public List<SchoolSearchResponseDto> searchSchoolsFromOpenApi(String keyword, String region) {
        if (neisApiKey == null || neisApiKey.isBlank()) {
            throw new IllegalStateException("NEIS_API_KEY is not configured");
        }
        List<SchoolSearchResponseDto> result = new ArrayList<>();

        int page = 1;
        boolean hasMore = true;

        while (hasMore) {
            String apiUrl = "https://open.neis.go.kr/hub/schoolInfo" +
                            "?KEY=" + neisApiKey +
                            "&Type=json" +
                            "&pIndex=" + page +
                            "&pSize=100";

            if (region != null && !region.isEmpty()) {
                apiUrl += "&LCTN_SC_NM=" + region;
            } else {
                apiUrl += "&LCTN_SC_NM=서울특별시";
            }

            if (keyword != null && !keyword.isEmpty()) {
                apiUrl += "&SCHUL_NM=" + keyword;
            }

            try {
                String jsonString = restTemplate.getForObject(apiUrl, String.class);
                JSONObject jsonObject = new JSONObject(jsonString);

                JSONArray rowArray = jsonObject
                                        .getJSONArray("schoolInfo")
                                        .getJSONObject(1)
                                        .getJSONArray("row");

                if (rowArray.length() == 0) {
                    break;
                }

                for (int i = 0; i < rowArray.length(); i++) {
                    JSONObject school = rowArray.getJSONObject(i);
                    String kind = school.optString("SCHUL_KND_SC_NM", "");
                    if (!kind.equals("고등학교") && !kind.equals("중학교")) continue;

                    String name = school.getString("SCHUL_NM");
                    String address = school.optString("ORG_RDNMA", "");

                    SchoolEntity entity = schoolRepository.findBySchoolName(name).orElse(null);

                    if (entity == null) {
                        entity = new SchoolEntity();
                        entity.setSchoolName(name);
                        entity.setAddress(address);
                        schoolRepository.save(entity);
                        log.debug("학교 정보를 저장했습니다.");
                    }

                    result.add(new SchoolSearchResponseDto(entity.getId(), name, address));
                }

                if (rowArray.length() < 100) {
                    hasMore = false;
                } else {
                    page++;
                }

            } catch (Exception e) {
                // HTTP 예외 메시지에는 API 키가 포함된 요청 URL이 들어갈 수 있다.
                log.error("교육부 학교 API 조회 실패: {}", e.getClass().getSimpleName());
                hasMore = false;
            }
        }

        return result;
    }  

    @Override
    public boolean verifyStudent(StudentVerifyDto dto) {
        return studentRepository.findByStudentNumber(dto.getStudentNumber().trim()).isPresent();
    }
}
