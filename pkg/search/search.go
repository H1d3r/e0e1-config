package search

import (
	"bytes"
	"fmt"
	"golang.org/x/text/transform"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"e0e1-config/pkg/search/guize"
	"e0e1-config/pkg/search/guolv"
	"e0e1-config/pkg/search/jiexi"
)

func UpdateFileTypes(fileTypes map[string]string, key, value string) {

	if value != "" {
		fileTypes[key] = value
	}
}

func CompileRegexes(regexList []string) ([]*regexp.Regexp, error) {
	var compiledRegexes []*regexp.Regexp

	for _, r := range regexList {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, err
		}
		compiledRegexes = append(compiledRegexes, re)
	}

	return compiledRegexes, nil
}

func SearchConfigFiles(path string, info os.FileInfo, allRegexes []*regexp.Regexp, customFileTypeList string, extenOnlyFlag bool, sizeLimit int64, charLimit int) ([]string, error) {
	var results []string

	size := info.Size()

	if info.IsDir() && size > sizeLimit {
		return results, nil
	}

	ext := filepath.Ext(path)

	if ext == "" {
		return results, nil
	}
	fileType := ""

	if extenOnlyFlag == false {
		UpdateFileTypes(guize.FileTypes, "custom", customFileTypeList)
		for k, v := range guize.FileTypes {
			if strings.Contains(v, ext+",") {
				fileType = k
				break
			}
		}
	} else {
		UpdateFileTypes(guize.CusFileTypes, "custom", customFileTypeList)
		for k, v := range guize.CusFileTypes {
			if strings.Contains(v, ext+",") {
				fileType = k
				break
			}
		}
	}

	if fileType == "" {
		return results, nil
	}

	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		return results, err
	}
	enc, err := jiexi.DetectEncoding(fileContent)
	if err != nil {
		return results, nil
	}

	reader := transform.NewReader(bytes.NewReader(fileContent), enc.NewDecoder())
	lines, err := ioutil.ReadAll(reader)
	if err != nil {
		return results, err
	}

	var matchedContents []string

	for _, line := range bytes.Split(lines, []byte{'\n'}) {

		var blacklistBytes [][]byte
		for _, item := range guize.Blacklist {
			blacklistBytes = append(blacklistBytes, []byte(item))
		}

		if guolv.ContainsAny(line, blacklistBytes) {
			continue
		}

		lineStr := strings.TrimSpace(string(line))
		if len(lineStr) == 0 {
			continue
		}

		var matches []string
		for _, regex := range allRegexes {
			match := regex.FindStringSubmatch(lineStr)
			if len(match) > 1 {
				matches = append(matches, match[1])
			}
		}
		if len(matches) == 0 {
			continue
		}

		matchedContent := fmt.Sprintf("%s\n", lineStr)

		if utf8.RuneCountInString(matchedContent) <= charLimit {
			matchedContents = append(matchedContents, matchedContent)
		}
	}

	if len(matchedContents) > 0 {
		var buffer bytes.Buffer

		lines := strings.Split(strings.TrimSpace(strings.Join(matchedContents, "\n")), "\n")

		maxLen := 0
		for _, line := range lines {
			if length := len(line); length > maxLen {
				maxLen = length
			}
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return results, err
		}
		buffer.WriteString(fmt.Sprintf("File: %s\n", absPath))

		for _, line := range lines {
			for _, line := range strings.Split(line, "\n") {
				for _, regex := range guize.TeZhengList {
					re := regexp.MustCompile(regex)
					if re.MatchString(line) {
						fmt.Printf("\n%s\n", line)
					}
				}
			}

			prefix := strings.Repeat(" ", 2)
			paddedLine := fmt.Sprintf("%-*s\n", maxLen, line)

			buffer.WriteString(prefix)
			buffer.WriteString(paddedLine)
		}

		results = append(results, buffer.String())
	}

	return results, nil
}

type SearchOptions struct {
	Path               string
	UserRegexList      []string
	UserOnlyFlag       bool
	CustomFileTypeList string
	ExtenOnlyFlag      bool
	SizeLimit          int64
	CharLimit          int
}

func Search(options SearchOptions) (string, error) {
	//获取cpu核心数
	numCores := runtime.NumCPU()
	maxWorkers := numCores / 2
	if maxWorkers <= 1 {
		maxWorkers = 1
	}

	if _, err := os.Stat(options.Path); os.IsNotExist(err) {
		return "", fmt.Errorf("路径 %s 不存在，请输入正确路径", options.Path)
	}

	var CompiledRegexes []*regexp.Regexp
	var err error

	if options.UserOnlyFlag {
		CompiledRegexes, err = CompileRegexes(options.UserRegexList)
	} else {
		allRegexes := append(guize.RegexList, options.UserRegexList...)
		CompiledRegexes, err = CompileRegexes(allRegexes)
	}

	if err != nil {
		return "", fmt.Errorf("编译正则表达式失败: %v", err)
	}

	fmt.Println("正在搜索文件，路径:", options.Path)
	fmt.Println("这可能需要一些时间，请稍候...")

	resultChan := make(chan []string)
	errChan := make(chan error)
	fastCodeHistoryChan := make(chan string)

	pool := make(chan struct{}, maxWorkers)

	go func() {
		err := filepath.Walk(options.Path, func(path string, info os.FileInfo, err error) error {
			pool <- struct{}{}
			defer func() { <-pool }()

			if err != nil {
				return nil
			}
			if info.IsDir() {
				for _, name := range guize.DirNamesToSkip {
					if info.Name() == name {
						return filepath.SkipDir
					}
				}
			}

			if err != nil {
				fmt.Println("获取绝对路径失败:", err)
				return nil
			}

			res, err := SearchConfigFiles(path, info, CompiledRegexes, options.CustomFileTypeList, options.ExtenOnlyFlag, options.SizeLimit, options.CharLimit)
			if err != nil {
				errChan <- err
				return nil
			}
			if len(res) > 0 {
				resultChan <- res
			}

			return nil
		})
		if err != nil {
			errChan <- err
		}

		close(resultChan)
		close(fastCodeHistoryChan)
	}()

	start := time.Now()
	numScannedFiles := 0
	var resultSummary strings.Builder

	for {
		select {
		case results, ok := <-resultChan:
			if !ok {
				end := time.Now()
				summary := fmt.Sprintf("\n搜索完成，时间: %s。总搜索时间: %v。\n", end.Format(time.RFC3339), end.Sub(start))
				fmt.Print(summary)
				//resultSummary.WriteString(summary)
				return resultSummary.String(), nil
			}
			for _, result := range results {
				resultSummary.WriteString(result + "\n")
			}

			numScannedFiles++
			prefix := fmt.Sprintf("正在扫描有效文件... %d", numScannedFiles)
			fmt.Printf("\r%s", prefix)
			fmt.Print("\033[0K")

		case fastCodeHistory, ok := <-fastCodeHistoryChan:
			if !ok {
				continue
			}
			resultSummary.WriteString(fastCodeHistory + "\n")

		case err := <-errChan:
			if err != nil {
				fmt.Println("搜索文件时出错:", err)
			}
		}
	}
}
