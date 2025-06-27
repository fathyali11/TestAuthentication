namespace UsersManagement.DTOS.Requests;

public record PagedRequest(int PageIndex = PaginationConstants.DefaultPageIndex,
    int PageSize = PaginationConstants.DefaultPageSize,
    string? SearchTerm = null,
    string? SortBy = null,
    string? SortDirection = "asc"
);
