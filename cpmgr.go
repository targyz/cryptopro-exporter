//MIT License
//
//Copyright (c) 2020 targyz
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type CPMgr struct {
	Cpconfig string
	Certmgr  string
	Cryptcp  string
}

// getVersion запускает утилиту cryptcp
// и возвращает номер версии криптопро или ошибку
func (m *CPMgr) getVersion() (version float64, err error) {
	c := exec.Command(m.Cryptcp, "-sn")
	out, err := c.Output()
	r := regexp.MustCompile(`CryptCP\s+(?P<VersionNumber>\d+.\d+)\s+`)

	matches := r.FindStringSubmatch(string(out))
	if matches == nil || len(matches) < 2 || matches[1] == "" {
		return 0, errors.New(fmt.Sprintf("version number not found: %#v", string(out)))
	}
	version, err = strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("can not extract version number: %v", err))
	}
	return
}

// getLicenseDays запускает утилиту сpconfig,
// анализирует её вывод и возвращает информацию о лицензии тремя значениями:
// isPermanent - флаг постоянной лицензии, если true - устанавливает expiresIn=9999999
// isActive - флаг активности лицензии
// expiresIn - количество дней, через которое лицензия истечет
func (m *CPMgr) getLicenseInfo() (isPermanent bool, isActive bool, expiresIn int, err error) {

	c := exec.Command(m.Cpconfig, "-license", "-view")
	out, err := c.Output()

	if err != nil {
		return
	}

	s := string(out)

	expiresIn = 9999999
	isActive = !strings.Contains(s, "expired")
	isPermanent = strings.Contains(s, "permanent")

	if !isActive {
		expiresIn = 0
		return
	}

	if isPermanent {
		return
	}

	hasMonth := strings.Contains(s, "month")
	s = strings.Replace(s, "(s)", "", -1)

	if hasMonth {
		r := regexp.MustCompile(`Expires: (?P<Months>\d+) month (?P<Days>\d+) day`)

		matches := r.FindStringSubmatch(s)
		if matches == nil {
			return false, false, 0, errors.New("failed to find expiry info")
		}

		i1, er := strconv.Atoi(matches[1])

		if er != nil {
			return false, false, 0, errors.New("failed to process expiry info")

		}
		i2, er := strconv.Atoi(matches[2])

		if er != nil {
			return false, false, 0, errors.New("failed to process expiry info")
		}

		expiresIn = i1*30 + i2

	} else {
		r := regexp.MustCompile(`Expires: (?P<Days>\d+) day`)
		matches := r.FindStringSubmatch(s)
		if matches == nil {
			return false, false, 0, errors.New("failed to process expiry info")
		}

		i1, err := strconv.Atoi(matches[1])

		if err != nil {
			return false, false, 0, errors.New("failed to process expiry info")
		}

		expiresIn = i1
	}

	return
}

// GetUserCertsInfo запускает утилиту сertmgr
// анализирует её вывод и возвращает информацию о пользовательских сертификатах или ошибку:
// containerNames - список имен контейнеров
// expireIn - список с датами истечения сертификатов
func (m *CPMgr) GetUserCertsInfo() (containerNames []string, expireIn []float64, err error) {

	c := exec.Command(m.Certmgr, "-list")
	out, err := c.Output()

	if err != nil {
		return
	}

	s := string(out)

	r1 := regexp.MustCompile(`HDIMAGE\\\\(?P<containername>\w+)\.000`)
	matchesContainerNames := r1.FindStringSubmatch(s)
	if matchesContainerNames == nil || len(matchesContainerNames) < 2 || matchesContainerNames[1] == "" {
		err = errors.New("containers not found")
		return
	}

	containerNames = matchesContainerNames[1:]

	r2 := regexp.MustCompile(`Not valid after\s+:\s+(?P<notValidAfterDate>\d{2}/\d{2}/\d{4})\s+`)
	matchesNotValidAfterDates := r2.FindStringSubmatch(s)
	if matchesNotValidAfterDates == nil || len(matchesNotValidAfterDates) < 2 || matchesNotValidAfterDates[1] == "" {
		err = errors.New("certificate valid date not found")
		return
	}

	notValidAfterDates := matchesNotValidAfterDates[1:]
	for _, d := range notValidAfterDates {
		expireIn = append(expireIn, diffDaysFromNow(d))
	}

	return
}
