from datetime import datetime

class Account:
    """
    Банковский счет с историей операций и базовыми финансовыми операциями.
    
    Реализует основные функции банковского счета: управление балансом,
    проведение операций и ведение полной истории транзакций.
    """
    def __init__(self, account_holder: str, account_name, balance: float = 0.0):
        """
        Создает новый банковский счет.

        Args:
            account_holder: Владелец счета
            account_name: Название счета
            balance: Начальный баланс (по умолчанию 0.0)
        """
        self.account_holder = account_holder
        self.account_name = account_name
        self.__balance = balance
        self.operations_history = []

    def get_balance(self):
        return self.__balance

    def deposit(self, amount):
        if amount > 0:
            old_balance = self.__balance
            self.__balance += amount
            operation = {
                'type': 'deposit',
                'amount': amount,
                'date_time': datetime.now(),
                'balance_after': self.__balance,
                'status': 'Success'
            }
            self.operations_history.append(operation)
            return f"Счет пополнен на {amount}. Новый баланс: {self.__balance}"
        else:
            #Записываем неудачную операцию
            operation = {
                'type': 'deposit',
                'amount': amount,
                'date_time': datetime.now(),
                'balance_after': self.__balance,
                'status': 'Fail'
            }
            self.operations_history.append(operation)
            return "Сумма пополнения должна быть положительной"

    def withdraw(self, amount: float):
        """Снятие со счета"""
        if amount > 0:
            if amount <= self.__balance:
                self.__balance -= amount
                # Добавляем успешную операцию в историю
                operation = {
                    'type': 'withdraw',
                    'amount': amount,
                    'date_time': datetime.now(),
                    'balance_after': self.__balance,
                    'status': 'Success'
                }
                self.operations_history.append(operation)
                return f"Снятие со счета {amount}. Новый баланс: {self.__balance}"
        else:
            # Записываем неудачную операцию
            operation = {
                'type': 'withdraw',
                'amount': amount,
                'date_time': datetime.now(),
                'balance_after': self.__balance,
                'status': 'Fail'
            }
            self.operations_history.append(operation)
            return "Недостаточно средств для снятия"

    def get_history(self):
        """
        Возвращает историю операций
        """
        return self.operations_history

    def get_formatted_history(self):
        """
        Возвращает отформатированную историю операций (дополнительный метод)
        """
        if not self.operations_history:
            return "История операций пуста"

        history_str = "История операций:\n"
        for i, operation in enumerate(self.operations_history, 1):
            history_str += f"{i}. {operation['type'].upper()} | "
            history_str += f"Сумма: {operation['amount']} | "
            history_str += f"Дата: {operation['date_time'].strftime('%Y-%m-%d %H:%M:%S')} | "
            history_str += f"Баланс после: {operation['balance_after']} | "
            history_str += f"Статус: {operation['status']}\n"
        return history_str

"""
Проверка
"""
account = Account("Иван Иванов", "Основной счет")

print(account.get_balance())
print(account.deposit(-3000))
print(account.deposit(3000))
print(account.withdraw(2000))
print(account.withdraw(3000))
print(account.deposit(-100))
print(account.withdraw(-300))

history = account.get_history()
print("\nПолная история операций (сырые данные):")
for operation in history:
    print(operation)

print("\n" + "="*50 + "\n")

# Или в отформатированном виде
print(account.get_formatted_history())

print("\n" + "="*50 + "\n")

# Фильтрация истории
successful_operations = [operation for operation in history if operation['status'] == 'Success']
print(f"Успешных операций: {len(successful_operations)}")  # Должно быть 2

deposits = [operation for operation in history if operation['type'] == 'deposit' and operation['status'] == 'Success']
print(f"Успешных пополнений: {len(deposits)}")  # Должно быть 1

withdrawals = [operation for operation in history if operation['type'] == 'withdraw' and operation['status'] == 'Success']
print(f"Успешных снятий: {len(withdrawals)}")  # Должно быть 1

failed_operations = [operation for operation in history if operation['status'] == 'Fail']
print(f"Неудачных операций: {len(failed_operations)}")  # Должно быть 2
