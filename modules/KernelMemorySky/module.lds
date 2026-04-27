SECTIONS {
    .text   : { *(.text) }
    .kpm.info   : { *(.kpm.info) }
    .kpm.init   : { *(.kpm.init) }
    .kpm.ctl0   : { *(.kpm.ctl0) }
    .kpm.ctl1   : { *(.kpm.ctl1) }
    .kpm.exit   : { *(.kpm.exit) }
}