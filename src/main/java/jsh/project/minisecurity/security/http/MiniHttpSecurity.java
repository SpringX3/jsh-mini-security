package jsh.project.minisecurity.security.http;

import jakarta.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

public class MiniHttpSecurity {

    private boolean csrfEnabled = true;
    private final List<Filter> filters = new ArrayList<>();
    private final List<AuthorizationRule> rules = new ArrayList<>();

    public MiniHttpSecurity() {
        
    }
}
