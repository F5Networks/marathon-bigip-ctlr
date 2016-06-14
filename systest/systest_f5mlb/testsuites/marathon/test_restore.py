"""Test suite to verify f5mlb's ability to restore target configs."""


import time

from pytest import meta_suite, meta_test

from . import utils


pytestmark = meta_suite(tags=["func", "marathon", "restore"])


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_backend_create(marathon, f5mlb):
    """Verify response when unmanaged bigip objects are added.

    When it realizes that unmanaged bigip objects have been added, f5mlb will
    do nothing.
    """
    # - add unmanaged virtual server
    # - add unmanaged pool
    # - add unmanaged pool member
    # - add unmanaged node
    # - add unmanaged health monitor
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_backend_update(marathon, f5mlb):
    """Verify response when managed bigip objects are modified.

    When it realizes that managed bigip objects were modified, f5mlb will
    reset the properties that it cares about and ignore the properties that it
    doesn't care about.
    """
    # - modify managed virtual server
    # - modify managed pool
    # - modify managed pool member
    # - modify managed node
    # - modify managed health monitor
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_backend_delete(marathon, f5mlb):
    """Verify response when managed bigip objects are deleted.

    When it realizes that managed bigip objects were deleted, f5mlb will
    recreate them.
    """
    # - delete managed virtual server
    # - delete managed pool
    # - delete managed pool member
    # - delete managed node
    # - delete managed health monitor
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_partition_delete(marathon, f5mlb):
    """Verify response when partition with f5mlb objects is deleted.

    When it realizes that a partition with managed objects was deleted, f5mlb
    will recreate them on another managed partition (if there is one).
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_delete(marathon, f5mlb):
    """Verify response when f5mlb is deleted (no other changes occur).

    Neither the bigip nor managed service are changed while f5mlb is gone, so
    there's nothing for f5mlb to do when it comes back online.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_delete_then_svc_delete(marathon, f5mlb):
    """Verify response when f5mlb and the managed service are deleted.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned and reaps them.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_delete_then_svc_update(marathon, f5mlb):
    """Verify response when f5mlb deleted, then managed service is changed.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned (because the managed service is no longer properly
    configured to register with f5mlb) and reaps them.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_delete_then_backend_delete(marathon, f5mlb):
    """Verify response when f5mlb and backend objects are deleted.

    When the f5mlb comes back online, it realizes that managed bigip objects
    are missing, so it creates new ones.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_delete_then_backend_update(marathon, f5mlb):
    """Verify response when f5mlb deleted, then backend objects are changed.

    When the f5mlb comes back online, it realizes that managed bigip objects
    were modified, so it resets the properties that it cares about and ignores
    the properties that it doesn't care about.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_suspend(marathon, f5mlb):
    """Verify response when f5mlb is suspended (no other changes occur).

    Neither the bigip nor managed service are changed while f5mlb is gone, so
    there's nothing for f5mlb to do when it comes back online.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_suspend_then_svc_delete(marathon, f5mlb):
    """Verify response when f5mlb suspended, then managed service is deleted.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned and reaps them.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_suspend_then_svc_update(marathon, f5mlb):
    """Verify response when f5mlb suspended, then managed service is changed.

    When the f5mlb comes back online, it realizes that the managed bigip
    objects are orphaned (because the managed service is no longer properly
    configured to register with f5mlb) and reaps them.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_suspend_then_backend_delete(marathon, f5mlb):
    """Verify response when f5mlb suspended, then backend objects are deleted.

    When the f5mlb comes back online, it realizes that managed bigip objects
    are missing, so it creates new ones.
    """
    pass


@meta_test(id="f5mlb-x", tags=["incomplete"])
def test_restore_after_f5mlb_suspend_then_backend_update(marathon, f5mlb):
    """Verify response when f5mlb suspended, then backend objects are changed.

    When the f5mlb comes back online, it realizes that managed bigip objects
    were modified, so it resets the properties that it cares about and ignores
    the properties that it doesn't care about.
    """
    pass
