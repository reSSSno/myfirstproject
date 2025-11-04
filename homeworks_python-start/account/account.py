from datetime import datetime

class Account:
    def __init__(self, account_holder: str, account_name, balance: float = 0.0):
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
        if self.__balance >= amount:
            old_balance = self.__balance
            self.__balance -= amount
            operation = {
                'type': 'withdraw',
                'amount': amount,
                'date_time': datetime.now(),
                'balance_after': self.__balance,
                'status': 'Success'
            }
            self.operations_history.append(operation)
            return f"Снятие средств со счета на {amount}. Новый баланс: {self.__balance}"
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
account1 = Account("Иван Иванов", "Основной счет")

print(account1.get_balance())
print(account1.deposit(3000))
print(account1.withdraw(2000))

history = account1.get_history()
print("\nПолная история операций (сырые данные):")
for operation in history:
    print(operation)

print("\n" + "="*50 + "\n")

# Или в отформатированном виде
print(account1.get_formatted_history())

print("\n" + "="*50 + "\n")

# Можно фильтровать историю
successful_operations = [op for op in history if op['status'] == 'success']
print(f"Успешных операций: {len(successful_operations)}")

deposits = [op for op in history if op['type'] == 'deposit' and op['status'] == 'success']
print(f"Успешных пополнений: {len(deposits)}")
