/* SPDX-License-Identifier: GPL-2.0-or-later */

SECTIONS
{
    .kpm : {
        *(.kpm.info)
        *(.kpm.init)
        *(.kpm.ctl0)
        *(.kpm.ctl1)
        *(.kpm.exit)
    }
}
