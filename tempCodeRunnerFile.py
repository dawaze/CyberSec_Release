c.execute(
                "INSERT INTO crypto_logs (user_id, cipher_type, operation, input_text, result, date) "
                "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                (current_user.id, cipher_type, operation, text, result)
            )