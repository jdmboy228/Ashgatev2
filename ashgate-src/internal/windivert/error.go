package windivert

import (
	"errors"
	"fmt"
	"syscall"
)

// FormatError turns a WinDivert or Win32 failure into a short Russian message.
// The numeric code is always included so an unlisted failure can still be identified.
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	var n syscall.Errno
	if !errors.As(err, &n) || n == 0 {
		return err.Error()
	}
	msg := errnoText(n)
	if msg == "" {
		return fmt.Sprintf("ошибка WinDivert %d", int(n))
	}
	return fmt.Sprintf("%s (код %d)", msg, int(n))
}

func errnoText(n syscall.Errno) string {
	switch n {
	case 2:
		return "не найдены WinDivert.dll или WinDivert64.sys рядом с программой"
	case 5:
		return "Нет прав администратора или перехват уже занят другой копией Ashgate/другой программой (Proxifier, zapret/winws, GoodbyeDPI). Закройте их и запустите Ashgate от имени администратора."
	case 87:
		return "WinDivert отклонил фильтр"
	case 126, 127:
		return "не удалось загрузить WinDivert.dll"
	case 232:
		return "очередь WinDivert закрыта"
	case 577:
		return "подпись WinDivert64.sys отклонена; попробуйте вариант драйвера A, B или C"
	case 654:
		return "уже загружена несовместимая копия драйвера WinDivert"
	case 1060:
		return "служба драйвера WinDivert не установлена"
	case 1232:
		return "внедрённый пакет не доставлен (хост недоступен)"
	case 1275:
		return "драйвер WinDivert заблокирован политикой Windows или антивирусом"
	case 1753:
		return "служба Base Filtering Engine отключена"
	default:
		return ""
	}
}

// IsNoData reports the ERROR_NO_DATA that WinDivertRecv returns after Shutdown.
func IsNoData(err error) bool {
	var n syscall.Errno
	return errors.As(err, &n) && n == 232
}

// IsInvalidHandle reports ERROR_INVALID_HANDLE (6).
func IsInvalidHandle(err error) bool {
	var n syscall.Errno
	return errors.As(err, &n) && n == 6
}
