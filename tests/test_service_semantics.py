from guardian.service_semantics import classify_service_observation


def test_systemd_empty_failure_set_is_healthy() -> None:
    result = classify_service_observation(
        "systemd_failed",
        "0 loaded units listed.",
    )

    assert result == {
        "status": "healthy",
        "reason": "no failed systemd units found",
        "counts": {"failed": 0},
        "parsed": True,
    }


def test_systemd_execution_failure_is_not_object_failure() -> None:
    result = classify_service_observation(
        "systemd_failed",
        "permission denied while executing systemctl",
    )

    assert result["status"] == "execution_failed"
    assert result["parsed"] is False


def test_docker_observation_is_structured() -> None:
    result = classify_service_observation(
        "docker",
        "\n".join(
            (
                '{"Names":"api","State":"running","Health":"healthy"}',
                '{"Names":"worker","State":"running","Health":"healthy"}',
            )
        ),
    )

    assert result["status"] == "healthy"
    assert result["counts"] == {
        "running": 2,
        "exited": 0,
        "restarting": 0,
        "healthy": 2,
        "unhealthy": 0,
    }


def test_unknown_observation_is_explicitly_unsupported() -> None:
    result = classify_service_observation("future_collector", "some output")

    assert result["status"] == "unsupported"
    assert result["parsed"] is False
