namespace PasswordManager.UI.Components.Shared;

/// <summary>
/// Inner SVG markup (24x24 viewBox, stroke-based) for each named icon.
/// Rendered by <see cref="Icon"/>; stroke color comes from currentColor.
/// </summary>
public static class Icons
{
    public static readonly IReadOnlyDictionary<string, string> Paths = new Dictionary<string, string>
    {
        ["lock"] = """<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>""",
        ["lock-keyhole"] = """<rect x="4" y="10" width="16" height="10" rx="2.5"/><path d="M7.5 10V7a4.5 4.5 0 0 1 9 0v3"/><circle cx="12" cy="15" r="1.4"/>""",
        ["shield"] = """<path d="M12 3l7 3v5c0 4.4-3 8.3-7 9.5C8 19.3 5 15.4 5 11V6z"/>""",
        ["shield-check"] = """<path d="M12 3l7 3v5c0 4.4-3 8.3-7 9.5C8 19.3 5 15.4 5 11V6z"/><path d="M9.5 12l1.8 1.8L15 10"/>""",
        ["key"] = """<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3"/><path d="M15 8l3 3"/>""",
        ["home"] = """<path d="M3 11l9-8 9 8"/><path d="M5 10v9h14v-9"/>""",
        ["note"] = """<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4"/><path d="M9 12h6M9 16h6"/>""",
        ["card"] = """<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18"/>""",
        ["refresh"] = """<path d="M4 12a8 8 0 0 1 13.7-5.7L20 8"/><path d="M20 4v4h-4"/><path d="M20 12a8 8 0 0 1-13.7 5.7L4 16"/><path d="M4 20v-4h4"/>""",
        ["book"] = """<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 19a2 2 0 0 1 2-2h13"/>""",
        ["search"] = """<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>""",
        ["copy"] = """<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>""",
        ["eye"] = """<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>""",
        ["eye-off"] = """<path d="M3 3l18 18"/><path d="M10.6 5.1A10.9 10.9 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3 3.9"/><path d="M6.1 6.1A17.4 17.4 0 0 0 2 12s3.5 7 10 7c1.4 0 2.7-.3 3.9-.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>""",
        ["chevron-right"] = """<path d="M9 6l6 6-6 6"/>""",
        ["chevron-down"] = """<path d="M6 9l6 6 6-6"/>""",
        ["menu"] = """<path d="M4 7h16M4 12h16M4 17h16"/>""",
        ["arrow-left"] = """<path d="M15 18l-6-6 6-6"/>""",
        ["check"] = """<path d="M20 6L9 17l-5-5"/>""",
        ["info"] = """<circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><circle cx="12" cy="16.5" r="0.6" fill="currentColor"/>""",
        ["alert"] = """<path d="M12 3l10 18H2z"/><path d="M12 10v4"/><circle cx="12" cy="17" r="0.6" fill="currentColor"/>""",
        ["file"] = """<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4"/>""",
        ["folder"] = """<path d="M3 6a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>""",
        ["plus"] = """<path d="M12 5v14M5 12h14"/>""",
        ["x"] = """<path d="M6 6l12 12M18 6L6 18"/>""",
        ["clock"] = """<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>""",
        ["download"] = """<path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M4 21h16"/>""",
        ["upload"] = """<path d="M12 15V3"/><path d="M7 8l5-5 5 5"/><path d="M4 21h16"/>""",
        ["swap"] = """<path d="M7 4v13"/><path d="M3 8l4-4 4 4"/><path d="M17 20V7"/><path d="M13 16l4 4 4-4"/>""",
        ["trash"] = """<path d="M4 7h16"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><path d="M6 7l1 13h10l1-13"/>""",
        ["edit"] = """<path d="M4 20l4-1L20 7l-3-3L5 16z"/><path d="M14 6l3 3"/>""",
        ["user"] = """<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/>""",
        ["list"] = """<path d="M4 6h1M4 12h1M4 18h1"/><path d="M9 6h11M9 12h11M9 18h11"/>""",
        ["grid"] = """<rect x="4" y="4" width="7" height="7" rx="2"/><rect x="13" y="4" width="7" height="7" rx="2"/><rect x="4" y="13" width="7" height="7" rx="2"/><rect x="13" y="13" width="7" height="7" rx="2"/>""",
        ["users"] = """<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.5 3-5.5 6.5-5.5s6.5 2 6.5 5.5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18.4 14.9c1.9.8 3.1 2.4 3.1 5.1"/>""",
        ["globe"] = """<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>""",
        ["mail"] = """<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6l9-6"/>""",
        ["phone"] = """<path d="M6 3h3l2 5l-2.5 1.5a12 12 0 0 0 5 5L16 14l5 2v3a2 2 0 0 1-2 2A16 16 0 0 1 4 5a2 2 0 0 1 2-2z"/>""",
        // Sliders rather than a gear: at the 14px the drawer draws it, a cogwheel's teeth
        // collapse into a fuzzy ring, while three rules and three handles stay readable.
        ["sliders"] = """<path d="M4 7h9M17 7h3"/><path d="M4 12h3M11 12h9"/><path d="M4 17h9M17 17h3"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="15" cy="17" r="2"/>""",
    };
}
