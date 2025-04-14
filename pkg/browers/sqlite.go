package browers

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	_ "github.com/glebarez/sqlite" // 导入 glebarez/sqlite 驱动
)

// SQLiteHandler 是一个使用纯Go实现的SQLite处理器
type SQLiteHandler struct {
	db         *sql.DB
	tableName  string
	fieldNames []string
	rows       []map[string]string
}

// NewSQLiteHandler 创建一个新的SQLite处理器
func NewSQLiteHandler(filePath string) (*SQLiteHandler, error) {
	// 打开SQLite数据库
	db, err := sql.Open("sqlite", filePath)
	if err != nil {
		return nil, fmt.Errorf("打开SQLite数据库失败: %v", err)
	}

	// 测试连接
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("连接SQLite数据库失败: %v", err)
	}

	return &SQLiteHandler{
		db:   db,
		rows: []map[string]string{},
	}, nil
}

// Close 关闭数据库连接
func (h *SQLiteHandler) Close() {
	if h.db != nil {
		h.db.Close()
	}
}

// GetTableNames 获取数据库中所有表名
func (h *SQLiteHandler) GetTableNames() []string {
	var tables []string

	query := `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
	rows, err := h.db.Query(query)
	if err != nil {
		fmt.Printf("获取表名列表时出错: %v\n", err)
		return tables
	}
	defer rows.Close()

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}
		tables = append(tables, tableName)
	}

	return tables
}

// ReadTable 读取指定表
func (h *SQLiteHandler) ReadTable(tableName string) bool {
	h.tableName = tableName
	h.rows = []map[string]string{}

	// 首先检查表是否存在
	var tableExists int
	checkTableQuery := `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`
	err := h.db.QueryRow(checkTableQuery, tableName).Scan(&tableExists)
	if err != nil {
		fmt.Printf("检查表 %s 是否存在时出错: %v\n", tableName, err)
		return false
	}

	if tableExists == 0 {
		fmt.Printf("[-] 没有查询到%s该信息\n", tableName)
		return false
	}

	// 获取表结构
	pragmaQuery := fmt.Sprintf("PRAGMA table_info(%s)", tableName)
	pragmaRows, err := h.db.Query(pragmaQuery)
	if err != nil {
		fmt.Printf("获取表 %s 结构时出错: %v\n", tableName, err)
		return false
	}
	defer pragmaRows.Close()

	// 读取字段名
	h.fieldNames = []string{}
	for pragmaRows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var dfltValue interface{}
		if err := pragmaRows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk); err != nil {
			fmt.Printf("扫描表结构时出错: %v\n", err)
			continue
		}
		h.fieldNames = append(h.fieldNames, name)
	}

	if len(h.fieldNames) == 0 {
		fmt.Printf("表 %s 没有字段\n", tableName)
		return false
	}

	//fmt.Printf("表 %s 有 %d 个字段\n", tableName, len(h.fieldNames))

	// 读取表数据
	dataQuery := fmt.Sprintf("SELECT * FROM %s LIMIT %s", tableName, browerlimit) // 限制行数以避免内存问题
	dataRows, err := h.db.Query(dataQuery)
	if err != nil {
		fmt.Printf("查询表 %s 数据时出错: %v\n", tableName, err)
		return false
	}
	defer dataRows.Close()

	// 获取列信息
	columns, err := dataRows.Columns()
	if err != nil {
		fmt.Printf("获取列信息时出错: %v\n", err)
		return false
	}

	// 准备扫描目标
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range columns {
		valuePtrs[i] = &values[i]
	}

	// 读取数据
	rowCount := 0
	for dataRows.Next() {
		if err := dataRows.Scan(valuePtrs...); err != nil {
			fmt.Printf("扫描行数据时出错: %v\n", err)
			continue
		}

		// 将数据转换为字符串映射
		rowData := make(map[string]string)
		for i, col := range columns {
			var v interface{} = values[i]

			// 处理不同类型的数据
			switch vt := v.(type) {
			case []byte:
				// 对于二进制数据，使用base64编码
				rowData[col] = base64.StdEncoding.EncodeToString(vt)
			case time.Time:
				// 时间格式化
				rowData[col] = vt.Format(time.RFC3339)
			case nil:
				rowData[col] = ""
			default:
				// 其他类型转为字符串
				rowData[col] = fmt.Sprintf("%v", v)
			}
		}

		h.rows = append(h.rows, rowData)
		rowCount++
	}

	//fmt.Printf("从表 %s 读取了 %d 行数据\n", tableName, rowCount)

	return len(h.rows) > 0
}

// GetRowCount 获取行数
func (h *SQLiteHandler) GetRowCount() int {
	return len(h.rows)
}

// GetValue 获取指定行列的值
func (h *SQLiteHandler) GetValue(rowIndex int, columnName string) string {
	if rowIndex < 0 || rowIndex >= len(h.rows) {
		return ""
	}

	return h.rows[rowIndex][columnName]
}

// FormatTime 格式化时间为字符串
func FormatTime(chromeTime int64) string {
	t := TimeEpoch(chromeTime)
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}
