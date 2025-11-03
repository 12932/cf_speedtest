pub fn format_ascii_table(rows: Vec<Vec<String>>) -> String {
    if rows.is_empty() {
        return String::new();
    }

    // Calculate column widths
    let mut col_widths = vec![0; rows[0].len()];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            col_widths[i] = col_widths[i].max(cell.len());
        }
    }

    let mut result = String::new();

    // Top border
    result.push('┌');
    for (i, &width) in col_widths.iter().enumerate() {
        result.push_str(&"─".repeat(width + 2));
        if i < col_widths.len() - 1 {
            result.push('┬');
        }
    }
    result.push_str("┐\n");

    // Header row
    result.push('│');
    for (i, cell) in rows[0].iter().enumerate() {
        result.push_str(&format!(" {:width$} ", cell, width = col_widths[i]));
        if i < rows[0].len() - 1 {
            result.push('┆');
        }
    }
    result.push_str("│\n");

    // Header separator
    result.push('╞');
    for (i, &width) in col_widths.iter().enumerate() {
        result.push_str(&"═".repeat(width + 2));
        if i < col_widths.len() - 1 {
            result.push('╪');
        }
    }
    result.push_str("╡\n");

    // Data rows
    for (row_idx, row) in rows.iter().skip(1).enumerate() {
        result.push('│');
        for (i, cell) in row.iter().enumerate() {
            result.push_str(&format!(" {:width$} ", cell, width = col_widths[i]));
            if i < row.len() - 1 {
                result.push('┆');
            }
        }
        result.push_str("│\n");

        // Add dotted separator between data rows (except for the last row)
        if row_idx < rows.len() - 2 {
            result.push('├');
            for (i, &width) in col_widths.iter().enumerate() {
                result.push_str(&"╌".repeat(width + 2));
                if i < col_widths.len() - 1 {
                    result.push('┼');
                }
            }
            result.push_str("┤\n");
        }
    }

    // Bottom border
    result.push('└');
    for (i, &width) in col_widths.iter().enumerate() {
        result.push_str(&"─".repeat(width + 2));
        if i < col_widths.len() - 1 {
            result.push('┴');
        }
    }
    result.push('┘');

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_table() {
        let rows = vec![
            vec!["".to_string(), "Header1".to_string(), "Header2".to_string()],
            vec!["Row1".to_string(), "Data1".to_string(), "Data2".to_string()],
        ];

        let result = format_ascii_table(rows);

        // Check that it contains the expected characters
        assert!(result.contains('┌'));
        assert!(result.contains('┐'));
        assert!(result.contains('└'));
        assert!(result.contains('┘'));
        assert!(result.contains('╞'));
        assert!(result.contains('╡'));
        assert!(result.contains('┆'));
        assert!(result.contains("Header1"));
        assert!(result.contains("Data1"));
    }

    #[test]
    fn test_empty_table() {
        let rows = vec![];
        let result = format_ascii_table(rows);
        assert_eq!(result, "");
    }

    #[test]
    fn test_three_rows_with_separator() {
        let rows = vec![
            vec!["".to_string(), "Median".to_string(), "Average".to_string()],
            vec![
                "DOWN".to_string(),
                "91.94 mbit/s".to_string(),
                "88.70 mbit/s".to_string(),
            ],
            vec![
                "UP".to_string(),
                "15.99 mbit/s".to_string(),
                "16.20 mbit/s".to_string(),
            ],
        ];

        let result = format_ascii_table(rows);

        // Should contain dotted separator between data rows
        assert!(result.contains('╌'));
        assert!(result.contains('┼'));
        assert!(result.contains("DOWN"));
        assert!(result.contains("UP"));
    }
}
