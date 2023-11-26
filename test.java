import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.finda.autolease.common.annotations.AuthorizeRequired;
import com.finda.autolease.common.enums.members.MemberTypeCode;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

class AuthorizeRequiredAspectTest {

    @InjectMocks
    private AuthorizeRequiredAspect aspect;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @Mock
    private MethodSignature signature;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
    }

    @Test
    void testAuthorizedAccess() throws Throwable {
        // 권한이 있는 사용자 설정
        when(authentication.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("MEMBER")));
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(mockMethodWithAuthorizeRequired(MemberTypeCode.MEMBER));

        // 권한이 있는 사용자에 대해 메소드가 정상적으로 진행되는지 테스트
        Object expectedReturnValue = new Object();
        when(joinPoint.proceed()).thenReturn(expectedReturnValue);
        Object actualReturnValue = aspect.handleAuthorizeRequired(joinPoint);

        assertEquals(expectedReturnValue, actualReturnValue);
    }

    @Test
    void testUnauthorizedAccess() throws Throwable {
        // 권한이 없는 사용자 설정
        when(authentication.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ANONYMOUS")));
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(mockMethodWithAuthorizeRequired(MemberTypeCode.MEMBER));

        // 권한이 없는 사용자에 대해 반환 값이 마스킹되는지 테스트
        TestObject returnValue = new TestObject();
        returnValue.setSensitiveField("sensitiveData");
        when(joinPoint.proceed()).thenReturn(returnValue);
        aspect.handleAuthorizeRequired(joinPoint);

        assertNull(returnValue.getSensitiveField());
    }

    private Method mockMethodWithAuthorizeRequired(MemberTypeCode memberTypeCode) {
        Method mockMethod = mock(Method.class);
        AuthorizeRequired authorizeRequired = mock(AuthorizeRequired.class);
        when(authorizeRequired.value()).thenReturn(memberTypeCode);
        when(mockMethod.getAnnotations()).thenReturn(new Annotation[]{authorizeRequired});
        return mockMethod;
    }

    static class TestObject {
        @AuthorizeRequired
        private String sensitiveField;

        public void setSensitiveField(String sensitiveField) {
            this.sensitiveField = sensitiveField;
        }

        public String getSensitiveField() {
            return sensitiveField;
        }
    }
}
