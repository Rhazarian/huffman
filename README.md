# huffman
## Задание №4
В данном задании необходимо реализовать библиотеку для сжатия Хаффманом.

Программа должна состоять из трех частей:
- Библиотека, которая реализует операции сжатия и распаковки.
- Консольная утилита, которая позволяет сжимать/распаковывать файлы на диске.
- Программа с набором тестов, проверяющая корректность библиотеки.
# Требования к библиотеке
- Библиотека должна компилироваться в отдельную статическую либо динамическую библиотеку и не должна зависеть ни от каких функций, определенных в консольной программе либо в программе-тестах.
- Библиотека должна предоставлять операции для сжатия/распаковки данных находящихся в оперативной памяти.
- Библиотека не должна использовать функции для работы с файлами напрямую.
- Интерфейс библиотеки должен быть достаточен, чтобы консольная утилита могла сжать/распаковать файл размером превосходящий размер доступной оперативной памяти.
# Требования к консольной утилите
- С помощь консольной утилиты должно быть возможно сжать один файл, записав в другой сжатое представление, а также распаковать файл со сжатым представлением, получив исходный файл.
- Попытка сжать пустой файл - это не ошибка. Должен получаться некоторый файл на выходе, при распаковке которого получится пустой файл.
- Консольная утилита не должна пытаться загружать весь файл в память целиком и должна работать в случае, когда сжимаемый/распаковываемый файл превосходит размер доступной оперативной памяти.
- Если распаковываемый файл поврежден, утилита должна выводить сообщение об ошибке, а не падать.
# Требования к тестам
- Тесты должны обеспечивать максимальное statement-покрытие (statement coverage), насколько это возможно.
