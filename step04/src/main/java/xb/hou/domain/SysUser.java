package xb.hou.domain;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @title: SysUser
 * @Author xbhou
 * @Date: 2021-06-24 15:41
 * @Version 1.0
 */
@Entity
@Getter
@Setter
@Table(name = "sys_user")
public class SysUser implements Serializable {
    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "age")
    private int age;

    @Column(name = "password")
    private String password;

    @Column(name = "user_name")
    private String userName;
}
