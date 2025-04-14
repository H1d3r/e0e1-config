module e0e1-config

go 1.21.5

replace golang.org/x/sys => golang.org/x/sys v0.15.0

require golang.org/x/crypto v0.0.0-20210921155107-089bfa567519

require (
	github.com/glebarez/sqlite v1.11.0
	github.com/mattn/go-sqlite3 v1.14.16
	golang.org/x/sys v0.25.0
	golang.org/x/text v0.13.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	gorm.io/gorm v1.25.7 // indirect
	modernc.org/libc v1.24.1 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.6.0 // indirect
	modernc.org/sqlite v1.25.0 // indirect
)
