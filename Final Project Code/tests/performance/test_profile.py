def test_profile_runs():
    import scripts.profile as prof
    # Just checking it can be imported without syntax errors
    assert hasattr(prof, "run_performance_test")
