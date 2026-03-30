#include <algorithm>
#include <iostream>
#include <locale>
#include <tuple>
#include <vector>
#include <regex>
#include <string>
#include <ctime>
#include <cstdlib>

#include "sqlite3.h"

// using a tuple to store user info (id, name, password)
typedef std::tuple<std::string, std::string, std::string> user_record;

// used to check if query has WHERE clause
const std::string str_where = " where ";

// forward declaration for sqlite callback
static int callback(void* possible_vector, int argc, char** argv, char** azColName);

// convert SQL to lowercase so I can check patterns easier
std::string normalize_sql(const std::string& sql)
{
    std::string normalized = sql;

    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return normalized;
}

// check if WHERE exists (most injections happen there)
bool has_where_clause(const std::string& normalized_sql)
{
    return normalized_sql.find(str_where) != std::string::npos;
}

// improved detection (algorithm enhancement)
// now I check multiple patterns instead of just one
bool is_suspected_injection(const std::string& sql)
{
    std::string normalized = normalize_sql(sql);

    // if there’s no WHERE, I skip checking
    if (!has_where_clause(normalized))
    {
        return false;
    }

    // list of common injection patterns
    std::vector<std::regex> patterns =
    {
        std::regex(".*or\\s+.*=.*"),        // OR 1=1
        std::regex(".*--.*"),               // comment injection
        std::regex(".*union\\s+select.*"),  // UNION attack
        std::regex(".*drop\\s+table.*"),    // DROP table
        std::regex(".*delete\\s+from.*")    // DELETE query
    };

    // loop through all patterns
    for (const auto& pattern : patterns)
    {
        if (std::regex_search(normalized, pattern))
        {
            return true;
        }
    }

    return false;
}

// unsafe execution (kept for comparison)
bool execute_sql(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    char* error_message = nullptr;

    // this runs raw SQL (not safe)
    if (sqlite3_exec(db, sql.c_str(), callback, &records, &error_message) != SQLITE_OK)
    {
        std::cout << "Query failed: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

// safe execution using prepared statements (database enhancement)
bool execute_safe_query(sqlite3* db, const std::string& name, std::vector<user_record>& records)
{
    sqlite3_stmt* stmt = nullptr;

    // using placeholder instead of inserting input directly
    std::string sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE NAME = ?";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    {
        std::cout << "Failed to prepare safe query." << std::endl;
        return false;
    }

    // bind input safely (this prevents SQL injection)
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        records.push_back(std::make_tuple(
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))
        ));
    }

    sqlite3_finalize(stmt);
    return true;
}

// sqlite callback
static int callback(void* possible_vector, int argc, char** argv, char** azColName)
{
    if (possible_vector == NULL)
    {
        for (int i = 0; i < argc; i++)
        {
            std::cout << azColName[i] << " = "
                      << (argv[i] ? argv[i] : "NULL") << std::endl;
        }
        std::cout << std::endl;
    }
    else
    {
        std::vector<user_record>* rows =
            static_cast<std::vector<user_record>*>(possible_vector);

        rows->push_back(std::make_tuple(argv[0], argv[1], argv[2]));
    }
    return 0;
}

// create database and insert test data
bool initialize_database(sqlite3* db)
{
    char* error_message = NULL;

    std::string sql = "CREATE TABLE USERS("
        "ID INT PRIMARY KEY NOT NULL,"
        "NAME TEXT NOT NULL,"
        "PASSWORD TEXT NOT NULL);";

    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Failed to create table: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    std::cout << "USERS table created." << std::endl;

    sql = "INSERT INTO USERS VALUES (1, 'Fred', 'Flinstone');"
          "INSERT INTO USERS VALUES (2, 'Barney', 'Rubble');"
          "INSERT INTO USERS VALUES (3, 'Wilma', 'Flinstone');"
          "INSERT INTO USERS VALUES (4, 'Betty', 'Rubble');";

    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Insert failed: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

// main query handler (NOW USES SAFE EXECUTION)
bool run_query(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    records.clear();

    // first check if it looks like injection
    if (is_suspected_injection(sql))
    {
        std::cout << "SECURITY ALERT: Possible SQL injection blocked." << std::endl;
        std::cout << "Blocked SQL: " << sql << std::endl << std::endl;
        return false;
    }

    // extract user input so I can run safe query
    size_t pos = sql.find("NAME='");
    if (pos != std::string::npos)
    {
        size_t start = pos + 6;
        size_t end = sql.find("'", start);
        std::string name = sql.substr(start, end - start);

        // use prepared statement instead of raw SQL
        return execute_safe_query(db, name, records);
    }

    // fallback for queries without user input
    return execute_sql(db, sql, records);
}

// simulate injection attempts
bool run_query_injection(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    std::string injectedSQL = sql;
    std::string localCopy = normalize_sql(sql);

    if (has_where_clause(localCopy))
    {
        if (!injectedSQL.empty() && injectedSQL.back() == ';')
        {
            injectedSQL.pop_back();
        }

        switch (rand() % 4)
        {
        case 1: injectedSQL += " or 2=2;"; break;
        case 2: injectedSQL += " or 'hi'='hi';"; break;
        case 3: injectedSQL += " or 'hack'='hack';"; break;
        default: injectedSQL += " or 1=1;"; break;
        }
    }

    return run_query(db, injectedSQL, records);
}

// print results
void dump_results(const std::string& sql, const std::vector<user_record>& records)
{
    std::cout << "\nSQL: " << sql
              << " ==> " << records.size() << " records found." << std::endl;

    for (auto record : records)
    {
        std::cout << "User: " << std::get<1>(record)
                  << " [UID=" << std::get<0>(record)
                  << " PWD=" << std::get<2>(record) << "]" << std::endl;
    }
}

// run queries
void run_queries(sqlite3* db)
{
    std::vector<user_record> records;

    std::string sql = "SELECT * from USERS";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE NAME='Fred'";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    for (int i = 0; i < 5; i++)
    {
        if (!run_query_injection(db, sql, records)) continue;
        dump_results(sql, records);
    }
}

// main
int main()
{
    srand(static_cast<unsigned int>(time(nullptr)));

    sqlite3* db = NULL;

    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
    {
        std::cout << "Database connection failed: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    std::cout << "Connected to database." << std::endl;

    if (!initialize_database(db))
    {
        std::cout << "Database setup failed." << std::endl;
        sqlite3_close(db);
        return -1;
    }

    run_queries(db);

    sqlite3_close(db);

    return 0;
}