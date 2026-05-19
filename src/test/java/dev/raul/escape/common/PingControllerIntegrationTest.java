package dev.raul.escape.common;

import dev.raul.escape.user.AppUser;
import dev.raul.escape.user.AppUserRepository;
import dev.raul.escape.user.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest
public class PingControllerIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository appUserRepository;

    @Test
    void shouldAllowPublicPing() throws Exception {
        mockMvc.perform(get("/api/public/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("public pong"));

    }

    @Test
    void shouldAllowPrivatePingForAuthenticatedUser() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "private-ping@example.com",
                                  "password": "password123",
                                  "displayName": "Private Ping User"
                                }
                                """))
                .andExpect(status().isCreated());

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "private-ping@example.com",
                                  "password": "password123"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest()
                .getSession(false);

        mockMvc.perform(get("/api/private/ping")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("private pong"));
    }

    @Test
    void shouldAllowAdminPingForAdminRole() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "admin@example.com",
                                  "password": "password123",
                                  "displayName": "Private Ping User"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"));

        AppUser user = appUserRepository.findByEmail("admin@example.com")
                .orElseThrow();

        user.setRole(Role.ADMIN);
        appUserRepository.save(user);


        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "admin@example.com",
                                  "password": "password123"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest()
                .getSession(false);

        mockMvc.perform(get("/api/admin/ping")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("admin pong"));
    }
}
