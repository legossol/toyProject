package kr.bora.api.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

@Entity
@Data
@Table(name="user")
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {

    @JsonIgnore
    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(name = "username", length = 50, unique = true)
    private String username;

    @JsonIgnore
    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "nickname", length = 50)
    private String nickname;

    @JsonIgnore
    @Column(name = "activated")
    private boolean activated;

    @Enumerated(EnumType.ORDINAL)
    private Role role;

    public Collection<Role> getRole() {
        Collection<Role> collectionRole =  new ArrayList<>(Arrays.asList(Role.values()));
        return collectionRole;
    }

//    protected List<Role> enumRoleToList = Arrays.asList(Role.values());
}
