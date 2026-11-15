/* Explicit opt-in physical host observation, outside synthetic CTest/CI. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "native_graphics.h"
#include "native_vblank.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    OotGraphics *graphics=oot_graphics_create();OotArm64State state={0},result;
    OotGraphicsPeerReport monitor={0},layer_report={0};OotDisplayReport before,after;
    OotVblankSnapshot snapshot;HANDLE data=NULL,failure=NULL,read=NULL;
    state.pc=0x1000;state.sp=0x8000;state.x[30]=0x2000;
    assert(graphics && !oot_graphics_call(graphics,OOT_GRAPHICS_BOOT,&state,&result));
    assert(!oot_graphics_call(graphics,OOT_DISPLAY_INITIALIZE,&state,&result));
    assert(oot_graphics_display_snapshot(graphics,&before));
    OotGraphicsDisplayPeer *display=oot_graphics_display_peer_open(graphics);
    assert(display && oot_graphics_display_peer_report(display,&monitor));
    assert(!oot_graphics_layer_peer_open(display,0,1080));
    OotGraphicsLayerPeer *layer=oot_graphics_layer_peer_open(display,1920,1080);
    assert(layer && oot_graphics_layer_peer_report(layer,&layer_report));
    assert(layer_report.width==1920 && layer_report.height==1080 && layer_report.dpi &&
        layer_report.visible && layer_report.presentation_supported);
    OotVblankSource *source=oot_vblank_create(oot_graphics_display_peer_monitor(display));
    assert(source && oot_vblank_duplicate_wait_handles(source,&data,&failure));
    assert(oot_vblank_duplicate_read(source,&read));
    assert(!ResetEvent(read) && GetLastError()==ERROR_ACCESS_DENIED);
    HANDLE waits[]={failure,data};
    for(unsigned n=0;n<16;++n){
        assert(WaitForMultipleObjects(2,waits,FALSE,1000)==WAIT_OBJECT_0+1);
        assert(oot_vblank_reset(source,1)==OOT_VBLANK_CLEARED);
    }
    assert(oot_vblank_snapshot(source,&snapshot) && snapshot.ready && !snapshot.failed && snapshot.ticks>=16);
    assert(CloseHandle(read) && CloseHandle(data) && CloseHandle(failure));oot_vblank_destroy(source);
    oot_graphics_layer_peer_close(layer);
    assert(oot_graphics_display_peer_live(display));oot_graphics_display_peer_close(display);
    assert(oot_graphics_display_snapshot(graphics,&after) && before.ready==after.ready &&
        before.calls==after.calls && before.initializations==after.initializations);
    oot_graphics_destroy(graphics);
    printf("{\"monitor_width\":%u,\"monitor_height\":%u,\"refresh_field\":%u,\"dpi\":%u,"
        "\"client_width\":1920,\"client_height\":1080,\"visible\":true,\"presentation_supported\":true,"
        "\"successful_waits_and_resets\":16,\"physical_edges_observed\":%llu,\"guest_code_executed\":false}\n",
        monitor.width,monitor.height,monitor.refresh,layer_report.dpi,(unsigned long long)snapshot.ticks);
    return 0;
}
