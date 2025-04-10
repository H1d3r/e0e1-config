module e0e1-config

go 1.21.5

replace golang.org/x/sys => golang.org/x/sys v0.15.0

require golang.org/x/crypto v0.0.0-20210921155107-089bfa567519

require (
	github.com/go-ini/ini v1.67.0
	github.com/shirou/gopsutil/v3 v3.24.5
	golang.org/x/sys v0.25.0
	golang.org/x/text v0.13.0
)

require (
	github.com/go-ole/go-ole v1.2.6
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c
	github.com/shoenig/go-m1cpu v0.1.6
	github.com/tklauser/go-sysconf v0.3.12
	github.com/tklauser/numcpus v0.6.1
	github.com/yusufpapurcu/wmi v1.2.4
)
